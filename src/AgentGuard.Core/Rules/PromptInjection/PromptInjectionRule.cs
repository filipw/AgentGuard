using System.Text.RegularExpressions;
using AgentGuard.Core.Abstractions;

using AgentGuard.Core.Rules;

namespace AgentGuard.Core.Rules.PromptInjection;

/// <summary>How aggressively <see cref="PromptInjectionRule"/> matches. Higher tiers add lower-precision patterns.</summary>
public enum Sensitivity
{
    /// <summary>Highest-confidence patterns only, minimal false positives.</summary>
    Low,

    /// <summary>Adds system-prompt extraction, jailbreak keywords, coercion and contradiction patterns. The default.</summary>
    Medium,

    /// <summary>Adds framing, inversion, link injection and bare chat-role markers. Trades precision for recall.</summary>
    High
}

/// <summary>Options for <see cref="PromptInjectionRule"/>.</summary>
public sealed class PromptInjectionOptions
{
    /// <summary>Which pattern tiers to run. Default: <see cref="Sensitivity.Medium"/>.</summary>
    public Sensitivity Sensitivity { get; init; } = Sensitivity.Medium;

    /// <summary>
    /// Additional regex patterns to match, beyond the built-in tiers. Validated and compiled when the
    /// rule is constructed, so an invalid pattern fails at startup rather than on the first request.
    /// </summary>
    public IList<string> CustomPatterns { get; init; } = [];

    /// <summary>When true (default), run the system-prompt extraction patterns.</summary>
    public bool BlockSystemPromptExtraction { get; init; } = true;

    /// <summary>When true (default), run the role/persona hijacking patterns.</summary>
    public bool BlockRolePlayAttacks { get; init; } = true;

    /// <summary>
    /// What to do when a pattern exceeds <see cref="MatchTimeout"/> and no other pattern matched.
    /// Default: <see cref="ErrorBehavior.FailOpen"/>, matching the other detection rules. Set to
    /// <see cref="ErrorBehavior.FailClosed"/> when a scan that cannot complete should block.
    /// </summary>
    /// <remarks>
    /// A timeout does not end the scan: the remaining patterns still run and the rule blocks if any
    /// of them matches, so this only decides the outcome when every pattern that did finish came
    /// back clean.
    /// </remarks>
    public ErrorBehavior OnError { get; init; } = ErrorBehavior.FailOpen;

    /// <summary>
    /// Per-pattern match timeout. Default: 250 ms.
    /// </summary>
    /// <remarks>
    /// This bounds a single pattern. A pattern that times out is recorded and the scan carries on
    /// with the rest, so the whole-rule worst case is the number of patterns times this budget. The
    /// built-in patterns run in time linear in the input, and a warm evaluation of all of them
    /// takes roughly 0.01 ms on a typical prompt, so in practice only a very large input or a
    /// pathological custom pattern reaches the budget; bound input size upstream (for example with
    /// a token limit) if that matters. It is set well above the steady-state cost because the first
    /// match on a compiled pattern also pays IL generation, and a tighter budget turned a cold start
    /// into a skipped check.
    /// </remarks>
    public TimeSpan MatchTimeout { get; init; } = TimeSpan.FromMilliseconds(250);
}

/// <summary>The kind of attack a built-in pattern detects, used to honour the per-category options.</summary>
internal enum InjectionPatternCategory
{
    General,
    SystemPromptExtraction,
    RolePlay
}

/// <summary>
/// Regex-based prompt injection detection. Order 10 - runs before the ML classifiers so an obvious
/// attack is rejected without paying for inference.
/// </summary>
/// <remarks>
/// All built-in patterns are compiled once into static arrays. Earlier revisions called the static
/// <see cref="Regex"/> helpers, which share a 15-entry cache across the process - with roughly sixty
/// patterns that cache thrashes and every evaluation re-parses nearly all of them.
/// </remarks>
public sealed class PromptInjectionRule : IGuardrailRule
{
    private readonly PromptInjectionOptions _options;
    private readonly (Regex Pattern, GuardrailSeverity Severity)[] _builtInPatterns;
    private readonly Regex[] _customPatterns;

    // Patterns informed by the Arcanum Prompt Injection Taxonomy
    // (https://github.com/Arcanum-Sec/arc_pi_taxonomy, CC BY 4.0)
    //
    // Organized into three tiers. Low sensitivity uses only CorePatterns (highest-confidence
    // detections with minimal false positives). Medium adds MediumPatterns. High adds all.

    private const RegexOptions Opts =
        RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant;

    // the compile-time timeout only bounds the shared static instances; a rule configured with a
    // different MatchTimeout recompiles its own set (see BuildPatterns).
    private static readonly TimeSpan DefaultTimeout = TimeSpan.FromMilliseconds(250);

    /// <summary>Core patterns: direct instruction override, role hijacking, end sequences, variable expansion, security bypass, forged turns.</summary>
    private static readonly (string Pattern, InjectionPatternCategory Category)[] CoreSources =
    [
        // Direct instruction override
        (@"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules|guidelines|directions)", InjectionPatternCategory.General),
        (@"disregard\s+(all\s+)?(previous|prior|above)", InjectionPatternCategory.General),
        (@"forget\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules|context|guidelines)", InjectionPatternCategory.General),
        (@"new\s+(instructions|rules|persona)\s*:", InjectionPatternCategory.General),
        (@"override\s+(instructions|rules|guidelines|system\s+prompt)", InjectionPatternCategory.General),
        (@"system\s*prompt\s*:", InjectionPatternCategory.General),

        // Role/persona hijacking
        (@"you\s+are\s+now\s+a", InjectionPatternCategory.RolePlay),
        (@"pretend\s+(you\s+are|to\s+be)\s+", InjectionPatternCategory.RolePlay),
        (@"act\s+as\s+if\s+you\s+(are|were)\s+", InjectionPatternCategory.RolePlay),
        (@"act\s+as\s+an?\s+(malicious|evil|unrestricted|unfiltered|uncensored|compromised|rogue|harmful|dangerous)\b", InjectionPatternCategory.RolePlay),
        // developer mode jailbreak
        (@"developer\s+mode\s+(is\s+)?(now\s+)?(enabled?|activated?|on)", InjectionPatternCategory.RolePlay),

        // Security bypass - direct attempts to disable safety mechanisms
        (@"bypass\s+(the\s+)?(security|safety|guardrails?|filters?|restrictions?|protections?)", InjectionPatternCategory.General),
        (@"disable\s+(\w+\s+)?(safety|security|guardrails?|filters?|restrictions?|protections?)", InjectionPatternCategory.General),
        (@"ignore\s+(the\s+)?(safety|security|ethical)\s+(guidelines?|rules?|restrictions?|measures?)", InjectionPatternCategory.General),
        (@"(uncensored|unfiltered|unrestricted)\s*(mode|response|output|version)", InjectionPatternCategory.General),
        (@"(without|no)\s+(any\s+)?(restrictions?|limitations?|guardrails?|safety\s+filters?)\s*($|[.,;!?])", InjectionPatternCategory.General),

        // Forged assistant turn - a user message that speaks as the model. Unlike "System:" or
        // "User:", which appear constantly in pasted logs and transcripts, an "Assistant:" /
        // "AI:" / "Bot:" line in user input is almost never ordinary prose.
        (@"(?:^|\n)[ \t]*(?:ASSISTANT|AI|BOT|MODEL)[ \t]*:[ \t]*\S", InjectionPatternCategory.General),

        // Any chat-role marker carrying a directive. The marker alone is weak evidence (see
        // HighSources); paired with an instruction cue it is a forged system turn.
        (@"(?:^|\n)[ \t]*(?:SYSTEM|USER|HUMAN|DEVELOPER|ASSISTANT|AI)[ \t]*:[ \t]*"
         + @"(?:you\s|your\s|ignore\b|disregard\b|forget\b|override\b|bypass\b|enable\b|disable\b|activate\b|"
         + @"new\b|from\s+now\s+on\b|always\b|never\b|do\s+not\b|don't\b|must\b|act\s+as\b|pretend\b|"
         + @"reveal\b|repeat\b|print\b|output\b|here\s+is\b|here's\b)", InjectionPatternCategory.General),

        // End sequence injection - 8 closure families from the Arcanum taxonomy
        // Token delimiters
        (@"<\|endoftext\|>", InjectionPatternCategory.General),
        (@"<\|im_start\|>", InjectionPatternCategory.General),
        (@"<\|im_end\|>", InjectionPatternCategory.General),
        (@"<\|eot_id\|>", InjectionPatternCategory.General),
        (@"<\|start_header_id\|>", InjectionPatternCategory.General),
        // Fake chat roles (require line-start position to avoid matching in-prose references).
        // the line start is a lookbehind checked once the marker itself is found, and the indent
        // in it cannot cross a newline, which keeps the scan linear.
        (@"(?<=(?:^|\n)[^\S\n]*)\[system\]", InjectionPatternCategory.General),
        (@"(?<=(?:^|\n)[^\S\n]*)<\s*system\s*>", InjectionPatternCategory.General),
        (@"\[\s*INST\s*\]", InjectionPatternCategory.General),
        (@"\[/\s*INST\s*\]", InjectionPatternCategory.General),
        (@"<<\s*SYS\s*>>", InjectionPatternCategory.General),
        (@"<\|assistant\|>", InjectionPatternCategory.General),
        (@"<\|user\|>", InjectionPatternCategory.General),
        // Bracketed frames
        (@"\[START\s+(OUTPUT|INSTRUCTIONS|SYSTEM)\]", InjectionPatternCategory.General),
        (@"\[END\s+(OUTPUT|INSTRUCTIONS|SYSTEM)\]", InjectionPatternCategory.General),
        // JSON/YAML boundary markers
        (@"""role""\s*:\s*""system""", InjectionPatternCategory.General),
        // Soft boundaries used as context separators
        (@"[-=]{5,}\s*(SYSTEM|END|BEGIN|RESET|OVERRIDE)\s*[-=]*", InjectionPatternCategory.General),
        (@"#{3,}\s*(SYSTEM|END|BEGIN|RESET)", InjectionPatternCategory.General),

        // HTML comment injection - hidden directives in document content. The body is bounded so a
        // long line of unclosed "<!-- system" openers cannot drive a quadratic scan.
        (@"<!--\s*(?:system|ignore|instruction|prompt|override)[^>\n]{0,200}?-->", InjectionPatternCategory.General),

        // Variable expansion attacks
        (@"\$\{(system_prompt|instructions|config|prompt)\}", InjectionPatternCategory.General),
        (@"\{\{(system_prompt|instructions|config|prompt)\}\}", InjectionPatternCategory.General),
        (@"%\{(system_prompt|instructions|config|prompt)\}", InjectionPatternCategory.General),
    ];

    /// <summary>Medium patterns: system prompt extraction, jailbreak, rule addition, anti-harm coercion, contradiction.</summary>
    private static readonly (string Pattern, InjectionPatternCategory Category)[] MediumSources =
    [
        // System prompt extraction
        (@"what\s+(is|are)\s+your\s+(system\s+)?(instructions|prompt|rules)", InjectionPatternCategory.SystemPromptExtraction),
        (@"(show|reveal|display|print|output)\s+(\w+\s+){0,3}system\s+(prompt|instructions)", InjectionPatternCategory.SystemPromptExtraction),
        (@"(reveal|display|print|output|extract|dump|leak)\s+(\w+\s+){0,3}(prompt|instructions)", InjectionPatternCategory.SystemPromptExtraction),
        (@"repeat\s+(your\s+)?(initial|original|system)\s+(\w+\s+){0,5}(prompt|instructions|message)", InjectionPatternCategory.SystemPromptExtraction),

        // Jailbreak keywords
        (@"DAN\s+mode", InjectionPatternCategory.General),
        (@"jailbr(eak|oken|eaking)", InjectionPatternCategory.General),
        (@"do\s+anything\s+now", InjectionPatternCategory.General),

        // Rule addition / modification
        (@"(new|additional|updated)\s+rule\s*:", InjectionPatternCategory.General),
        // the optional comma owns the whitespace after it, which keeps the scan linear
        (@"(from\s+now\s+on|henceforth|going\s+forward)\s*(?:,\s*)?(you\s+)?(must|should|will|shall)", InjectionPatternCategory.General),

        // Anti-harm coercion - pressuring the model to override safety by framing refusal as harmful
        (@"(refusing|failure)\s+to\s+(comply|help|assist|respond)\s+(is|would\s+be|causes?)(\s+\w+){0,5}\s+(harmful|dangerous|unethical|immoral|harm)", InjectionPatternCategory.General),
        (@"you\s+(must|have\s+to|need\s+to)\s+(comply|obey|help|answer)\s+(or|otherwise)", InjectionPatternCategory.General),
        (@"it\s+would\s+be\s+(unethical|immoral|wrong|harmful)\s+(not\s+to|to\s+refuse|to\s+decline)", InjectionPatternCategory.General),
        (@"(ethical|moral)\s+(duty|obligation|imperative)\s+to\s+(help|comply|answer|respond)", InjectionPatternCategory.General),
        (@"(people|someone|lives?)\s+(will|could|might)\s+(be\s+)?(hurt|harmed|die|suffer)\s+if\s+you\s+(don't|do\s+not|refuse)", InjectionPatternCategory.General),

        // Contradiction - presenting conflicting instructions to confuse safety logic
        (@"(your\s+)?(actual|real|true|original)\s+(instructions|rules|purpose)\s+(are|is|say)", InjectionPatternCategory.General),
        (@"(the\s+)?(previous|above)\s+(instructions?|rules?)\s+(are|were|was)\s+(wrong|incorrect|fake|a\s+test)", InjectionPatternCategory.General),
        (@"(contrary\s+to|despite|regardless\s+of)\s+(what|your)\s+(you\s+were|previous|system)\s+(told|instructions|prompt)", InjectionPatternCategory.General),
    ];

    /// <summary>High-sensitivity patterns: framing attacks, inversion, double-negative extraction, link injection, bare role markers.</summary>
    private static readonly (string Pattern, InjectionPatternCategory Category)[] HighSources =
    [
        // Framing attacks
        (@"(imagine|suppose|assume)\s+you\s+(are|have|were)\s+(an?\s+)?(unrestricted|unfiltered|uncensored)", InjectionPatternCategory.RolePlay),
        (@"for\s+a\s+fictional\s+(story|scenario|world)\s+where", InjectionPatternCategory.RolePlay),
        (@"in\s+a\s+hypothetical\s+(scenario|world)\s+where\s+(there\s+are\s+)?no\s+(rules|restrictions|limits)", InjectionPatternCategory.RolePlay),

        // Inversion / double-negative extraction
        (@"what\s+would\s+you\s+(not|never)\s+do\s+if", InjectionPatternCategory.SystemPromptExtraction),
        (@"list\s+(the\s+)?(things|topics)\s+you('re|\s+are)\s+(forbidden|not\s+allowed|unable)", InjectionPatternCategory.SystemPromptExtraction),

        // Link injection - malicious directives embedded in URLs or references. The link body is
        // bounded so an unclosed bracket cannot drive a quadratic scan, and the URL form starts only at
        // the beginning of a non-space run and commits to the first scheme in it.
        (@"(?<!\S)(?>\S*?https?://)\S*?(system_prompt|ignore_rules|jailbreak|override|injection)", InjectionPatternCategory.General),
        // the keyword search is atomic: if the link does not close within reach of the keyword nearest
        // the closing parenthesis, it cannot for any earlier one either, so those are not retried.
        (@"\[[^\]\n]{0,200}\]\((?>[^)\n]{0,200}(ignore|override|system|jailbreak|injection))[^)\n]{0,200}\)", InjectionPatternCategory.General),

        // Bare chat-role markers. Weak evidence on their own - a pasted log line ("System: the build
        // failed") or a support transcript ("User: hi / Agent: hello") trips them - so they only run
        // at the tier that explicitly trades precision for recall. The forged-turn and
        // marker-plus-directive variants in CoreSources cover the high-confidence cases. Line
        // starts use the same linear lookbehind as the fake chat roles above.
        (@"(?<=(?:^|\n)[^\S\n]*)SYSTEM\s*:", InjectionPatternCategory.General),
        (@"(?<=(?:^|\n)[^\S\n]*)USER\s*:", InjectionPatternCategory.General),
        (@"(?<=(?:^|\n)[^\S\n]*)HUMAN\s*:", InjectionPatternCategory.General),
        (@"(?<=(?:^|\n)[^\S\n]*)DEVELOPER\s*:", InjectionPatternCategory.General),
    ];

    private static readonly Regex[] CoreDefault = Compile(CoreSources, DefaultTimeout);
    private static readonly Regex[] MediumDefault = Compile(MediumSources, DefaultTimeout);
    private static readonly Regex[] HighDefault = Compile(HighSources, DefaultTimeout);

    /// <summary>Initializes a new instance of the <see cref="PromptInjectionRule"/> class.</summary>
    /// <param name="options">Configuration. When null, defaults are used.</param>
    /// <exception cref="ArgumentException">A custom pattern is not a valid regular expression.</exception>
    public PromptInjectionRule(PromptInjectionOptions? options = null)
    {
        _options = options ?? new();

        if (_options.MatchTimeout <= TimeSpan.Zero)
            throw new ArgumentException("MatchTimeout must be greater than zero.", nameof(options));

        _builtInPatterns = BuildPatterns(_options);
        _customPatterns = CompileCustom(_options);
    }

    /// <inheritdoc />
    public string Name => "prompt-injection";

    /// <inheritdoc />
    public GuardrailPhase Phase => GuardrailPhase.Input;

    /// <inheritdoc />
    public int Order => 10;

    /// <inheritdoc />
    public ValueTask<GuardrailResult> EvaluateAsync(GuardrailContext context, CancellationToken cancellationToken = default)
    {
        var text = context.Text;
        if (string.IsNullOrWhiteSpace(text))
            return ValueTask.FromResult(GuardrailResult.Passed());

        // a pattern that cannot finish within MatchTimeout is a scan we could not complete, not a
        // verdict: the remaining patterns still run and any of them can block. OnError decides only
        // when nothing matched.
        var timedOut = 0;

        foreach (var (pattern, severity) in _builtInPatterns)
        {
            switch (TryIsMatch(pattern, text))
            {
                case true:
                    return ValueTask.FromResult(
                        GuardrailResult.Blocked("Potential prompt injection detected.", severity));
                case null:
                    timedOut++;
                    break;
            }
        }

        foreach (var pattern in _customPatterns)
        {
            switch (TryIsMatch(pattern, text))
            {
                case true:
                    return ValueTask.FromResult(
                        GuardrailResult.Blocked("Input matched a custom injection pattern.", GuardrailSeverity.High));
                case null:
                    timedOut++;
                    break;
            }
        }

        if (timedOut > 0)
        {
            return ValueTask.FromResult(GuardrailResult.Error(
                Name, _options.OnError,
                $"{timedOut} pattern(s) exceeded the {_options.MatchTimeout.TotalMilliseconds:F0} ms match timeout and no other pattern matched"));
        }

        return ValueTask.FromResult(GuardrailResult.Passed());
    }

    /// <summary>Matches, returning <c>null</c> rather than throwing when the pattern times out.</summary>
    private static bool? TryIsMatch(Regex pattern, string text)
    {
        try
        {
            return pattern.IsMatch(text);
        }
        catch (RegexMatchTimeoutException)
        {
            return null;
        }
    }

    private static Regex[] Compile((string Pattern, InjectionPatternCategory Category)[] sources, TimeSpan timeout)
    {
        var compiled = sources.Select(s => new Regex(s.Pattern, Opts, timeout)).ToArray();

        // compiled patterns generate IL on first use, inside the match timeout; pay it here
        RegexPatterns.Warm(compiled);
        return compiled;
    }

    private static (Regex, GuardrailSeverity)[] BuildPatterns(PromptInjectionOptions options)
    {
        var useDefaults = options.MatchTimeout == DefaultTimeout;

        var tiers = new List<((string, InjectionPatternCategory)[] Sources, Regex[] Compiled, GuardrailSeverity Severity)>
        {
            (CoreSources, CoreDefault, GuardrailSeverity.Critical),
        };

        if (options.Sensitivity is Sensitivity.Medium or Sensitivity.High)
            tiers.Add((MediumSources, MediumDefault, GuardrailSeverity.High));

        if (options.Sensitivity is Sensitivity.High)
            tiers.Add((HighSources, HighDefault, GuardrailSeverity.High));

        var result = new List<(Regex, GuardrailSeverity)>();
        foreach (var (sources, compiled, severity) in tiers)
        {
            var regexes = useDefaults ? compiled : Compile(sources, options.MatchTimeout);
            for (var i = 0; i < sources.Length; i++)
            {
                if (!IsCategoryEnabled(sources[i].Item2, options))
                    continue;
                result.Add((regexes[i], severity));
            }
        }

        return [.. result];
    }

    private static bool IsCategoryEnabled(InjectionPatternCategory category, PromptInjectionOptions options) => category switch
    {
        InjectionPatternCategory.SystemPromptExtraction => options.BlockSystemPromptExtraction,
        InjectionPatternCategory.RolePlay => options.BlockRolePlayAttacks,
        _ => true
    };

    private static Regex[] CompileCustom(PromptInjectionOptions options)
    {
        var compiled = new List<Regex>(options.CustomPatterns.Count);
        foreach (var pattern in options.CustomPatterns)
        {
            try
            {
                compiled.Add(new Regex(pattern, Opts, options.MatchTimeout));
            }
            catch (ArgumentException ex)
            {
                throw new ArgumentException(
                    $"CustomPatterns contains an invalid regular expression: '{pattern}'. {ex.Message}",
                    nameof(options), ex);
            }
        }

        return [.. compiled];
    }
}
