using System.Text;
using System.Text.RegularExpressions;
using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Rules.Normalization;

namespace AgentGuard.Core.Rules.ToolResult;

/// <summary>
/// Risk level assigned to a tool based on the type of data it returns.
/// Higher risk tools are more likely to contain indirect prompt injection.
/// </summary>
public enum ToolRiskLevel
{
    /// <summary>Low risk - structured data, internal APIs.</summary>
    Low = 0,

    /// <summary>Medium risk - documents, code, CRM data.</summary>
    Medium = 1,

    /// <summary>High risk - email, messaging, user-generated content.</summary>
    High = 2
}

/// <summary>
/// Action to take when indirect injection is detected in a tool result.
/// </summary>
public enum ToolResultAction
{
    /// <summary>Block the entire pipeline.</summary>
    Block,

    /// <summary>
    /// Sanitize the tool result by removing the detected injection. A match only marks where an
    /// injected instruction starts, so everything from the start of the matched line through the
    /// end of its paragraph (the next blank line, or the end of the content) is replaced with
    /// <see cref="ToolResultGuardrailOptions.SanitizationReplacement"/>. Content with no paragraph
    /// breaks loses everything from the matched line on; use <see cref="Block"/> when precision
    /// matters more than keeping the rest of the result.
    /// </summary>
    Sanitize
}

/// <summary>
/// Represents a tool result returned to the agent that should be inspected for indirect injection.
/// </summary>
public sealed class ToolResultEntry
{
    /// <summary>The name of the tool that produced this result.</summary>
    public required string ToolName { get; init; }

    /// <summary>The content returned by the tool.</summary>
    public required string Content { get; init; }

    /// <summary>
    /// Optional risk level override. If not set, the rule will use tool risk profiles
    /// or default to <see cref="ToolRiskLevel.Medium"/>.
    /// </summary>
    public ToolRiskLevel? RiskLevel { get; init; }

    /// <summary>Optional metadata about the tool result (e.g. source, timestamp).</summary>
    public IReadOnlyDictionary<string, object>? Metadata { get; init; }
}

/// <summary>
/// A detected injection in a tool result.
/// </summary>
public sealed class ToolResultViolation
{
    /// <summary>The tool name that returned the injected content.</summary>
    public required string ToolName { get; init; }

    /// <summary>The category of injection detected.</summary>
    public required string Category { get; init; }

    /// <summary>Description of the detected pattern.</summary>
    public required string Description { get; init; }

    /// <summary>The matched text fragment (truncated to 100 chars).</summary>
    public string? MatchedText { get; init; }
}

/// <summary>
/// Options for the tool result guardrail rule.
/// </summary>
public sealed class ToolResultGuardrailOptions
{
    /// <summary>
    /// Action to take when injection is detected. Default: Block.
    /// </summary>
    public ToolResultAction Action { get; init; } = ToolResultAction.Block;

    /// <summary>
    /// Tool-specific risk profiles. Key is tool name (case-insensitive), value is risk level.
    /// Tools at <see cref="ToolRiskLevel.Low"/> are checked with fewer patterns.
    /// Default: empty (all tools use <see cref="ToolRiskLevel.Medium"/>).
    /// </summary>
    public IDictionary<string, ToolRiskLevel> ToolRiskProfiles { get; init; } =
        new Dictionary<string, ToolRiskLevel>(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Tool names to skip entirely. Default: empty.
    /// </summary>
    public ISet<string> SkippedTools { get; init; } =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Whether to strip Unicode control characters, zero-width characters and Unicode tag
    /// characters (U+E0000-U+E007F) from the results handed back. Detection of those characters
    /// runs either way. Default: true.
    /// </summary>
    public bool StripUnicodeControl { get; init; } = true;

    /// <summary>
    /// Whether to detect base64-encoded injection payloads. Default: true.
    /// </summary>
    public bool DetectEncodedPayloads { get; init; } = true;

    /// <summary>
    /// Replacement text used when <see cref="Action"/> is <see cref="ToolResultAction.Sanitize"/>.
    /// Each removed span (see <see cref="ToolResultAction.Sanitize"/>) becomes one copy of it,
    /// inserted literally - <c>$</c> sequences are not regex substitutions. Default: "[FILTERED]".
    /// </summary>
    public string SanitizationReplacement { get; init; } = "[FILTERED]";

    /// <summary>
    /// Custom detection patterns to add. Each tuple is (category, description, pattern).
    /// </summary>
    public IReadOnlyList<(string Category, string Description, Regex Pattern)> CustomPatterns { get; init; } =
        Array.Empty<(string, string, Regex)>();
}

/// <summary>
/// Guards against indirect prompt injection in tool call results. Inspects content returned
/// by tools (emails, documents, API responses) for hidden instructions, role markers,
/// encoding tricks, and other injection patterns before the content reaches the LLM.
///
/// This rule complements <see cref="ToolCall.ToolCallGuardrailRule"/> which guards outbound
/// tool call arguments. This rule guards inbound tool results.
///
/// Callers place tool results under the <c>ToolResults</c> key in
/// <see cref="GuardrailContext.Properties"/> as <c>IReadOnlyList&lt;ToolResultEntry&gt;</c>.
///
/// Supports tool-specific risk profiles - high-risk tools (email, messaging) are checked
/// with additional patterns. Inspired by StackOneHQ/defender's approach to indirect injection.
///
/// Order 47 - runs after tool call argument guardrails (order 45) but before content safety (order 50).
/// </summary>
public sealed class ToolResultGuardrailRule : IGuardrailRule
{
    private readonly ToolResultGuardrailOptions _options;

    /// <summary>Well-known property key for tool results in GuardrailContext.Properties.</summary>
    public const string ToolResultsKey = "ToolResults";

    /// <summary>Well-known property key for violations found.</summary>
    public const string ViolationsKey = "ToolResultViolations";

    /// <summary>Well-known property key for sanitized results (when Action is Sanitize).</summary>
    public const string SanitizedResultsKey = "SanitizedToolResults";

    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(200);

    // === Core patterns: always checked ===

    private static readonly (string Category, string Description, Regex Pattern)[] CorePatterns =
    [
        // Role/system markers - attempts to hijack the conversation role. The line start is a
        // lookbehind checked once the marker is found, with an indent that cannot cross a newline,
        // which keeps the scan linear.
        ("RoleHijacking", "System role marker injection",
            new(@"(?i)(?<=(?:^|\n)[^\S\n]*)(?:system|assistant|developer)\s*:", RegexOptions.Compiled, RegexTimeout)),

        // Bracket-style role markers
        ("RoleHijacking", "Bracket role marker injection",
            new(@"(?i)\[(?:system|assistant|user|admin)\]:", RegexOptions.Compiled, RegexTimeout)),

        // Instruction override - classic indirect injection
        ("InstructionOverride", "Instruction override attempt",
            new(@"(?i)(?:ignore|forget|disregard|override|bypass)\s+(?:all\s+)?(?:previous|prior|above|earlier|your|the)\s+(?:instructions|rules|prompts|guidelines|context|directives|constraints|system\s+prompt)",
                RegexOptions.Compiled, RegexTimeout)),

        // New instruction injection - attempt to set new instructions
        ("InstructionOverride", "New instruction injection",
            new(@"(?i)(?:your\s+new\s+instructions?\s+(?:are|is)|from\s+now\s+on\s+you\s+(?:are|will|must|should)|you\s+(?:are|will)\s+now\s+(?:act|behave|respond)\s+as)",
                RegexOptions.Compiled, RegexTimeout)),

        // Chat ML / special token injection
        ("TokenInjection", "Chat ML token injection",
            new(@"<\|(?:im_start|im_end|system|user|assistant|endoftext|pad|sep)\|>",
                RegexOptions.Compiled, RegexTimeout)),

        // XML-style role tags. The optional slash owns the whitespace after it, which keeps the scan
        // linear.
        ("TokenInjection", "XML role tag injection",
            new(@"<\s*(?:/\s*)?(?:system|assistant|user|instruction|tool_response)\s*>",
                RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout)),

        // JSON-style injection - fake JSON role/instruction fields
        ("TokenInjection", "JSON-style role injection",
            new(@"(?i)""(?:system|role|instruction|prompt)""\s*:\s*""",
                RegexOptions.Compiled, RegexTimeout)),

        // Markdown/HTML hidden content - invisible to user but read by LLM
        ("HiddenContent", "HTML comment with instructions",
            new(@"<!--\s*(?:system|instruction|ignore|override|inject|secret|hidden)\b[^>]*-->",
                RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout)),

        // Invisible Unicode - zero-width characters carrying payload
        ("HiddenContent", "Zero-width character sequence",
            new(@"[\u200B\u200C\u200D\u2060\uFEFF]{3,}",
                RegexOptions.Compiled, RegexTimeout)),

        // Text direction override characters - can reverse visible text to hide payloads
        ("HiddenContent", "Text direction override characters",
            new(@"[\u202A-\u202E\u2066-\u2069]",
                RegexOptions.Compiled, RegexTimeout)),

        // Unicode tag characters (U+E0000-U+E007F) - invisible ASCII a model still reads ("ASCII
        // smuggling"). Each is a surrogate pair, U+DB40 then U+DC00-U+DC7F. The one legitimate
        // use is an emoji flag tag sequence (U+1F3F4, a short tag spec, a cancel tag, e.g. the
        // flag of Scotland), so tags within a few code points of a black flag are not flagged; the
        // lookbehind is bounded, which keeps the scan linear.
        ("HiddenContent", "Unicode tag characters",
            new(@"(?<!\uD83C\uDFF4(?:\uDB40[\uDC20-\uDC7E]){0,8})(?:\uDB40[\uDC00-\uDC7F])+",
                RegexOptions.Compiled, RegexTimeout)),

        // Data exfiltration - URLs that may exfiltrate context
        ("DataExfiltration", "Data exfiltration URL pattern",
            new(@"(?i)https?://[^\s]+[?&](?:data|token|key|secret|password|context|prompt|instruction|system)=",
                RegexOptions.Compiled, RegexTimeout)),

        // Prompt leaking instructions
        ("PromptLeaking", "Prompt leak instruction",
            new(@"(?i)(?:repeat|output|print|echo|show|reveal|display|return)\s+(?:the\s+)?(?:system\s+prompt|instructions|your\s+(?:rules|prompt|instructions|system\s+message))",
                RegexOptions.Compiled, RegexTimeout)),

        // Print everything above / output initialization
        ("PromptLeaking", "Print everything above",
            new(@"(?i)(?:print|output|show|repeat|display)\s+(?:everything|all|the\s+text)\s+(?:above\s+this\s+(?:line|point|message)|before\s+this|so\s+far)",
                RegexOptions.Compiled, RegexTimeout)),

        // Security bypass - attempts to disable safety systems
        ("SecurityBypass", "Security bypass attempt",
            new(@"(?i)(?:bypass|disable|turn\s+off|deactivate|remove)\s+(?:the\s+)?(?:safety|security|content\s+filter|guardrail|restriction|moderation|censorship)",
                RegexOptions.Compiled, RegexTimeout)),

        // Uncensored/unrestricted mode requests
        ("SecurityBypass", "Uncensored mode request",
            new(@"(?i)(?:enable|enter|switch\s+to|activate)\s+(?:uncensored|unrestricted|unfiltered|jailbreak|developer|god|sudo)\s+mode",
                RegexOptions.Compiled, RegexTimeout)),

        // Command execution - attempts to run commands/code
        ("CommandExecution", "Command execution directive",
            new(@"(?i)(?:execute|run|eval)\s+(?:the\s+following\s+)?(?:command|code|script|query|function)\s*[:\(]",
                RegexOptions.Compiled, RegexTimeout)),

        // Separator injection - long separator lines followed by injection-like keywords. A
        // separator only starts at the beginning of its run and the whitespace before the line
        // break cannot itself contain one, which keeps the scan linear.
        ("DelimiterManipulation", "Separator injection",
            new(@"(?:(?<![-=])[-=]{10,}|(?<![─═])[─═]{5,})[^\S\n]*\n\s*(?i)(?:system|instruction|important|new\s+(?:rules|instructions|prompt))\s*:",
                RegexOptions.Compiled, RegexTimeout)),
    ];

    // === High-risk patterns: only checked for high-risk tools ===

    private static readonly (string Category, string Description, Regex Pattern)[] HighRiskPatterns =
    [
        // Encoded payloads in tool results - suspicious in email/messaging content
        ("EncodedPayload", "Base64-encoded instruction block",
            new(@"(?i)(?:base64|decode|atob)\s*[:(]\s*[A-Za-z0-9+/=]{20,}",
                RegexOptions.Compiled, RegexTimeout)),

        // Action directives - telling the agent to do something
        ("ActionDirective", "Tool action directive",
            new(@"(?i)(?:please\s+)?(?:send|forward|reply|compose|draft|create|delete|update|modify|execute|run|call)\s+(?:an?\s+)?(?:email|message|response|reply|request|command|action)\s+(?:to|for|with|that|containing)\b",
                RegexOptions.Compiled, RegexTimeout)),

        // Social engineering - fake urgency or authority
        ("SocialEngineering", "Fake authority or urgency",
            new(@"(?i)(?:urgent|immediately|critical|mandatory|required|authorized|admin|supervisor|manager|ceo|cto)\s*[:-]\s*(?:you\s+must|please\s+(?:immediately|urgently)|action\s+required|do\s+not\s+ignore)",
                RegexOptions.Compiled, RegexTimeout)),

        // Delimiter manipulation - pretending to end tool output and start a new context
        ("DelimiterManipulation", "Fake tool output boundary",
            new(@"(?i)(?:---\s*end\s+(?:of\s+)?(?:tool|function|api)\s+(?:output|result|response)\s*---|===\s*(?:tool|function)\s+(?:result|output)\s*===)",
                RegexOptions.Compiled, RegexTimeout)),

        // Persona hijacking - attempting to make the agent assume a different identity
        ("PersonaHijacking", "Persona override attempt",
            new(@"(?i)(?:you\s+are\s+(?:now\s+)?(?:a|an|the)|act\s+as\s+(?:a|an|the)|pretend\s+(?:to\s+be|you\s+are))\s+(?:different|new|unrestricted|unfiltered|jailbroken|evil|DAN)\b",
                RegexOptions.Compiled, RegexTimeout)),

        // Privileged role assumption - claiming admin/root/superuser authority
        ("PersonaHijacking", "Privileged role assumption",
            new(@"(?i)(?:you\s+are\s+(?:now\s+)?(?:an?\s+)?|act\s+as\s+(?:an?\s+)?|pretend\s+(?:to\s+be\s+)?(?:an?\s+)?|switch\s+to\s+)(?:admin(?:istrator)?|root|superuser|sudo|operator|moderator)",
                RegexOptions.Compiled, RegexTimeout)),

        // DAN-style jailbreak - common jailbreak personas
        ("PersonaHijacking", "DAN jailbreak attempt",
            new(@"(?i)(?:DAN\s+mode|developer\s+mode)\s+(?:enabled|activated|on)",
                RegexOptions.Compiled, RegexTimeout)),

        // Leetspeak obfuscation of injection keywords
        ("Obfuscation", "Leetspeak injection keywords",
            new(@"(?i)(?:1gn[o0]r[3e]|f[o0]rg[3e]t|byp[a4]ss|syst[3e]m|[o0]v[3e]rr[i1]d[3e]|d[i1]sr[3e]g[a4]rd)\s+(?:pr[3e]v[i1][o0]us|[i1]nstruct[i1][o0]ns|rul[3e]s|pr[o0]mpt)",
                RegexOptions.Compiled, RegexTimeout)),
    ];

    // === Medium-risk patterns: checked for medium and high risk tools ===

    private static readonly (string Category, string Description, Regex Pattern)[] MediumRiskPatterns =
    [
        // Markdown/invisible text injection
        ("HiddenContent", "Markdown hidden text injection",
            new(@"\[(?:system|hidden|secret|instruction)\]\([^)]*\)",
                RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout)),

        // Markdown image injection - invisible images with payloads in alt text or URL
        ("HiddenContent", "Markdown image with injection payload",
            new(@"!\[(?:system|instruction|override|ignore|hidden)[^\]]*\]\([^)]+\)",
                RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout)),

        // Role playing setup in content
        ("InstructionOverride", "Role-play setup in content",
            new(@"(?i)\[(?:INST|SYS|SYSTEM)\].*?\[/(?:INST|SYS|SYSTEM)\]",
                RegexOptions.Compiled | RegexOptions.Singleline, RegexTimeout)),

        // Hex-encoded instructions
        ("EncodedPayload", "Hex-encoded content block",
            new(@"(?:\\x[0-9a-fA-F]{2}){8,}",
                RegexOptions.Compiled, RegexTimeout)),

        // Unicode escape sequences hiding payloads
        ("EncodedPayload", "Unicode escape sequence block",
            new(@"(?:\\u[0-9a-fA-F]{4}){6,}",
                RegexOptions.Compiled, RegexTimeout)),

        // HTML entities hiding payloads
        ("EncodedPayload", "HTML entity encoded content",
            new(@"(?:&#(?:x[0-9a-fA-F]{2,4}|\d{2,5});){6,}",
                RegexOptions.Compiled, RegexTimeout)),

        // ROT13 encoded instructions (common obfuscation)
        ("Obfuscation", "ROT13 decode instruction",
            new(@"(?i)(?:rot13|caesar)\s*[:(]\s*[a-zA-Z]{10,}",
                RegexOptions.Compiled, RegexTimeout)),

        // Fullwidth character obfuscation (U+FF00-U+FFEF used to bypass keyword detection)
        ("Obfuscation", "Fullwidth character obfuscation",
            new(@"[\uFF00-\uFFEF]{4,}",
                RegexOptions.Compiled, RegexTimeout)),
    ];

    /// <summary>
    /// Default tool risk profiles for common tool categories.
    /// Email/messaging tools are high risk, document/code tools are medium.
    /// </summary>
    public static IReadOnlyDictionary<string, ToolRiskLevel> DefaultToolRiskProfiles { get; } =
        new Dictionary<string, ToolRiskLevel>(StringComparer.OrdinalIgnoreCase)
        {
            // High risk - user-generated content, external messaging
            ["gmail"] = ToolRiskLevel.High,
            ["email"] = ToolRiskLevel.High,
            ["send_email"] = ToolRiskLevel.High,
            ["read_email"] = ToolRiskLevel.High,
            ["outlook"] = ToolRiskLevel.High,
            ["slack"] = ToolRiskLevel.High,
            ["teams"] = ToolRiskLevel.High,
            ["discord"] = ToolRiskLevel.High,
            ["chat"] = ToolRiskLevel.High,
            ["message"] = ToolRiskLevel.High,
            ["sms"] = ToolRiskLevel.High,

            // Medium risk - documents, code, CRM
            ["search"] = ToolRiskLevel.Medium,
            ["web_search"] = ToolRiskLevel.Medium,
            ["browse"] = ToolRiskLevel.Medium,
            ["read_file"] = ToolRiskLevel.Medium,
            ["get_document"] = ToolRiskLevel.Medium,
            ["github"] = ToolRiskLevel.Medium,
            ["jira"] = ToolRiskLevel.Medium,
            ["confluence"] = ToolRiskLevel.Medium,

            // Low risk - structured data, internal APIs
            ["calculator"] = ToolRiskLevel.Low,
            ["get_weather"] = ToolRiskLevel.Low,
            ["get_time"] = ToolRiskLevel.Low,
        };

    /// <summary>Initializes a new instance of the <see cref="ToolResultGuardrailRule"/> class.</summary>
    /// <param name="options">Action, risk profiles and detection toggles. Defaults when null.</param>
    public ToolResultGuardrailRule(ToolResultGuardrailOptions? options = null)
    {
        _options = options ?? new();

        // compiled patterns generate IL on first use; pay it here, not on the first request
        RegexPatterns.Warm(CorePatterns.Select(p => p.Pattern));
        RegexPatterns.Warm(MediumRiskPatterns.Select(p => p.Pattern));
        RegexPatterns.Warm(HighRiskPatterns.Select(p => p.Pattern));
        RegexPatterns.Warm(_options.CustomPatterns.Select(p => p.Pattern));
    }

    /// <inheritdoc />
    public string Name => "tool-result-guardrail";

    /// <inheritdoc />
    public GuardrailPhase Phase => GuardrailPhase.Output;

    /// <inheritdoc />
    public int Order => 47;

    /// <inheritdoc />
    public ValueTask<GuardrailResult> EvaluateAsync(GuardrailContext context, CancellationToken cancellationToken = default)
    {
        if (!context.Properties.TryGetValue(ToolResultsKey, out var resultsObj) ||
            resultsObj is not IReadOnlyList<ToolResultEntry> toolResults ||
            toolResults.Count == 0)
        {
            return ValueTask.FromResult(GuardrailResult.Passed());
        }

        var violations = new List<ToolResultViolation>();

        // cleaned results are produced whenever there is anything to hand back - a sanitized
        // violation, or an entry that only needed its hidden characters removed - so a caller that
        // substitutes SanitizedResultsKey never feeds the raw payload to the model.
        var cleanedResults = new List<ToolResultEntry>(toolResults.Count);
        var anyCleaned = false;

        foreach (var result in toolResults)
        {
            if (_options.SkippedTools.Contains(result.ToolName) || string.IsNullOrWhiteSpace(result.Content))
            {
                cleanedResults.Add(result);
                continue;
            }

            var riskLevel = GetRiskLevel(result);
            var raw = result.Content;

            // Stripping invisible characters is what lets a keyword broken up by zero-width joiners
            // match. It must not be the only text the patterns see, though: the hidden-character
            // patterns below are looking for exactly the characters it removes, so both forms are
            // scanned and each pattern reports at most once.
            var stripped = _options.StripUnicodeControl ? StripControlCharacters(raw) : raw;
            var wasStripped = !string.Equals(raw, stripped, StringComparison.Ordinal);
            var secondary = wasStripped ? stripped : null;

            var resultViolations = new List<ToolResultViolation>();

            // Always check core patterns
            CheckPatterns(result.ToolName, raw, secondary, CorePatterns, resultViolations);

            // Check medium-risk patterns for medium and high risk tools
            if (riskLevel >= ToolRiskLevel.Medium)
            {
                CheckPatterns(result.ToolName, raw, secondary, MediumRiskPatterns, resultViolations);
            }

            // Check high-risk patterns for high risk tools
            if (riskLevel >= ToolRiskLevel.High)
            {
                CheckPatterns(result.ToolName, raw, secondary, HighRiskPatterns, resultViolations);
            }

            // Check custom patterns
            CheckPatterns(result.ToolName, raw, secondary, _options.CustomPatterns, resultViolations);

            violations.AddRange(resultViolations);

            // Sanitize mode rewrites violating content; either mode still hands back the
            // hidden-character-free text, which is the whole point of StripUnicodeControl.
            var shouldSanitize = _options.Action == ToolResultAction.Sanitize && resultViolations.Count > 0;
            if (!shouldSanitize && !wasStripped)
            {
                cleanedResults.Add(result);
                continue;
            }

            var cleaned = shouldSanitize ? SanitizeContent(stripped, riskLevel) : stripped;
            anyCleaned = true;
            cleanedResults.Add(new ToolResultEntry
            {
                ToolName = result.ToolName,
                Content = cleaned,
                RiskLevel = result.RiskLevel,
                Metadata = result.Metadata
            });
        }

        if (violations.Count > 0)
        {
            context.Properties[ViolationsKey] = violations;

            if (_options.Action == ToolResultAction.Sanitize)
            {
                context.Properties[SanitizedResultsKey] = cleanedResults;

                return ValueTask.FromResult(new GuardrailResult
                {
                    IsModified = true,
                    Reason = $"Indirect injection detected and sanitized in {violations.Count} tool result(s)",
                    ModifiedText = context.Text,
                    Metadata = BuildMetadata(violations)
                });
            }

            var first = violations[0];
            return ValueTask.FromResult(new GuardrailResult
            {
                IsBlocked = true,
                Reason = $"Indirect injection detected in tool result from '{first.ToolName}': {first.Description}",
                Severity = GuardrailSeverity.Critical,
                Metadata = BuildMetadata(violations)
            });
        }

        // no violation, but hidden characters were removed: hand the cleaned results back so they,
        // not the originals, are what reaches the model.
        if (anyCleaned)
        {
            context.Properties[SanitizedResultsKey] = cleanedResults;

            return ValueTask.FromResult(new GuardrailResult
            {
                IsModified = true,
                Reason = "Invisible Unicode characters stripped from tool result(s)",
                ModifiedText = context.Text
            });
        }

        return ValueTask.FromResult(GuardrailResult.Passed());
    }

    private ToolRiskLevel GetRiskLevel(ToolResultEntry result)
    {
        // Explicit override on the entry
        if (result.RiskLevel.HasValue)
            return result.RiskLevel.Value;

        // User-configured profile
        if (_options.ToolRiskProfiles.TryGetValue(result.ToolName, out var configured))
            return configured;

        // Default profiles
        if (DefaultToolRiskProfiles.TryGetValue(result.ToolName, out var defaultLevel))
            return defaultLevel;

        // Heuristic: check if tool name contains high-risk keywords
        var name = result.ToolName;
        if (name.Contains("email", StringComparison.OrdinalIgnoreCase) ||
            name.Contains("mail", StringComparison.OrdinalIgnoreCase) ||
            name.Contains("message", StringComparison.OrdinalIgnoreCase) ||
            name.Contains("chat", StringComparison.OrdinalIgnoreCase) ||
            name.Contains("slack", StringComparison.OrdinalIgnoreCase) ||
            name.Contains("sms", StringComparison.OrdinalIgnoreCase))
        {
            return ToolRiskLevel.High;
        }

        return ToolRiskLevel.Medium;
    }

    /// <summary>
    /// Runs each pattern against <paramref name="primary"/> and, when supplied,
    /// <paramref name="secondary"/> (the same text with invisible characters removed), recording at
    /// most one violation per pattern.
    /// </summary>
    private static void CheckPatterns(
        string toolName,
        string primary,
        string? secondary,
        IReadOnlyList<(string Category, string Description, Regex Pattern)> patterns,
        List<ToolResultViolation> violations)
    {
        foreach (var (category, description, pattern) in patterns)
        {
            var match = TryMatch(pattern, primary);
            if (match is null && secondary is not null)
            {
                match = TryMatch(pattern, secondary);
            }

            if (match is not null)
            {
                violations.Add(new ToolResultViolation
                {
                    ToolName = toolName,
                    Category = category,
                    Description = description,
                    MatchedText = TruncateMatch(match.Value)
                });
            }
        }
    }

    private static Match? TryMatch(Regex pattern, string text)
    {
        try
        {
            var match = pattern.Match(text);
            return match.Success ? match : null;
        }
        catch (RegexMatchTimeoutException)
        {
            // Pattern timed out - skip it rather than blocking legitimate content
            return null;
        }
    }

    /// <summary>
    /// Removes the injected instructions from one tool result's content, for
    /// <see cref="ToolResultAction.Sanitize"/>.
    /// </summary>
    /// <remarks>
    /// A pattern match marks where an injection starts, not where it ends, so each match
    /// is widened to the whole line it starts on, through the end of its paragraph - the next
    /// blank line, or the end of the content - which also catches an instruction hard-wrapped over
    /// several lines, as plain-text email is. Lines before the match's line and paragraphs after
    /// it are kept, and each removed span becomes one copy of
    /// <see cref="ToolResultGuardrailOptions.SanitizationReplacement"/>, inserted literally. When a
    /// pattern times out, where its injection ends cannot be known, so the whole content is
    /// replaced instead.
    /// </remarks>
    private string SanitizeContent(string content, ToolRiskLevel riskLevel)
    {
        var matches = new List<(int Start, int End)>();

        var complete = CollectMatches(content, CorePatterns, matches)
            && (riskLevel < ToolRiskLevel.Medium || CollectMatches(content, MediumRiskPatterns, matches))
            && (riskLevel < ToolRiskLevel.High || CollectMatches(content, HighRiskPatterns, matches))
            && CollectMatches(content, _options.CustomPatterns, matches);

        if (!complete)
            return _options.SanitizationReplacement;

        return matches.Count == 0 ? content : RemoveInjectedParagraphs(content, matches, _options.SanitizationReplacement);
    }

    /// <summary>
    /// Adds every match of every pattern to <paramref name="matches"/>. Returns <c>false</c> when a
    /// pattern times out.
    /// </summary>
    private static bool CollectMatches(
        string content,
        IReadOnlyList<(string Category, string Description, Regex Pattern)> patterns,
        List<(int Start, int End)> matches)
    {
        foreach (var (_, _, pattern) in patterns)
        {
            try
            {
                foreach (Match match in pattern.Matches(content))
                    matches.Add((match.Index, match.Index + match.Length));
            }
            catch (RegexMatchTimeoutException)
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Replaces, for each match, the text from the start of the match's line to the end of the
    /// match's paragraph; overlapping spans are merged first. Linear in the content length.
    /// </summary>
    internal static string RemoveInjectedParagraphs(string content, List<(int Start, int End)> matches, string replacement)
    {
        // line breaks at a match's edges belong to the neighbouring lines, not to the match
        for (var i = 0; i < matches.Count; i++)
        {
            var (start, end) = matches[i];
            while (start < end && content[start] is '\r' or '\n')
                start++;
            while (end > start && content[end - 1] is '\r' or '\n')
                end--;
            matches[i] = (start, end);
        }

        matches.Sort((a, b) => a.Start.CompareTo(b.Start));

        var spans = new List<(int Start, int End)>();
        foreach (var (start, end) in matches)
        {
            if (spans.Count > 0 && start < spans[^1].End)
            {
                // starts inside the span being built, so its line is already covered; only its
                // end can carry the span on into a later paragraph
                if (end > spans[^1].End)
                    spans[^1] = (spans[^1].Start, ParagraphEnd(content, end));
                continue;
            }

            var lineStart = start == 0 ? 0 : content.LastIndexOf('\n', start - 1) + 1;
            var paragraphEnd = ParagraphEnd(content, end);

            if (spans.Count > 0 && lineStart <= spans[^1].End)
                spans[^1] = (spans[^1].Start, Math.Max(spans[^1].End, paragraphEnd));
            else
                spans.Add((lineStart, paragraphEnd));
        }

        var builder = new StringBuilder(content.Length);
        var copied = 0;
        foreach (var (start, end) in spans)
        {
            builder.Append(content, copied, start - copied).Append(replacement);
            copied = end;
        }

        return builder.Append(content, copied, content.Length - copied).ToString();
    }

    /// <summary>
    /// The end of the paragraph containing the character before <paramref name="position"/>: the
    /// line break ahead of the next blank line (the break itself is kept), or the end of the text.
    /// </summary>
    private static int ParagraphEnd(string content, int position)
    {
        var lineEnd = content.IndexOf('\n', position);
        while (lineEnd >= 0)
        {
            var nextStart = lineEnd + 1;
            var nextEnd = content.IndexOf('\n', nextStart);
            var nextLine = content.AsSpan(nextStart, (nextEnd < 0 ? content.Length : nextEnd) - nextStart);

            if (nextLine.IsWhiteSpace())
                return lineEnd > position && content[lineEnd - 1] == '\r' ? lineEnd - 1 : lineEnd;

            lineEnd = nextEnd;
        }

        return content.Length;
    }

    /// <summary>
    /// Removes zero-width, bidirectional-control and Unicode tag characters that could be used to
    /// hide payloads. Walks the text by code point, so the surrogate pairs that tag characters are
    /// encoded as are removed whole.
    /// </summary>
    private static string StripControlCharacters(string text) =>
        InvisibleCharacters.Remove(text, IsHiddenCharacter) ?? text;

    private static bool IsHiddenCharacter(Rune rune) => rune.Value switch
    {
        0x200B or 0x200C or 0x200D or 0x2060 or 0xFEFF or 0x00AD or 0x200E or 0x200F => true,
        >= 0x202A and <= 0x202E => true,
        >= 0x2066 and <= 0x2069 => true,
        _ => InvisibleCharacters.IsUnicodeTag(rune)
    };

    private static string TruncateMatch(string match)
    {
        return match.Length > 100 ? match[..100] + "..." : match;
    }

    private static Dictionary<string, object> BuildMetadata(List<ToolResultViolation> violations)
    {
        return new Dictionary<string, object>
        {
            ["violationCount"] = violations.Count,
            ["toolName"] = violations[0].ToolName,
            ["category"] = violations[0].Category,
            ["violations"] = violations.Select(v => $"{v.ToolName}: [{v.Category}] {v.Description}").ToArray()
        };
    }
}
