using System.Text.RegularExpressions;
using AgentGuard.Core.Abstractions;

namespace AgentGuard.Core.Rules.PromptInjection;

public enum Sensitivity { Low, Medium, High }

public sealed class PromptInjectionOptions
{
    public Sensitivity Sensitivity { get; init; } = Sensitivity.Medium;
    public IList<string> CustomPatterns { get; init; } = [];
    public bool BlockSystemPromptExtraction { get; init; } = true;
    public bool BlockRolePlayAttacks { get; init; } = true;
}

public sealed class PromptInjectionRule : IGuardrailRule
{
    private readonly PromptInjectionOptions _options;

    // Patterns informed by the Arcanum Prompt Injection Taxonomy
    // (https://github.com/Arcanum-Sec/arc_pi_taxonomy, CC BY 4.0)
    //
    // Organized into three tiers. Low sensitivity uses only CorePatterns (highest-confidence
    // detections with minimal false positives). Medium adds MediumPatterns. High adds all.

    /// <summary>Core patterns: direct instruction override, role hijacking, end sequences, variable expansion.</summary>
    private static readonly string[] CorePatterns =
    [
        // Direct instruction override
        @"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules)",
        @"disregard\s+(all\s+)?(previous|prior|above)",
        @"forget\s+(all\s+)?(previous|prior|above)\s+(instructions|context)",
        @"new\s+(instructions|rules|persona)\s*:",
        @"override\s+(instructions|rules|system\s+prompt)",
        @"system\s*prompt\s*:",

        // Role/persona hijacking
        @"you\s+are\s+now\s+a",
        @"pretend\s+(you\s+are|to\s+be)\s+",
        @"act\s+as\s+if\s+you\s+(are|were)\s+",
        @"act\s+as\s+an?\s+(malicious|evil|unrestricted|unfiltered|uncensored|compromised|rogue|harmful|dangerous)\b",

        // End sequence injection - 8 closure families from the Arcanum taxonomy
        // Token delimiters
        @"<\|endoftext\|>",
        @"<\|im_start\|>",
        @"<\|im_end\|>",
        @"<\|eot_id\|>",
        @"<\|start_header_id\|>",
        // Fake chat roles (require line-start position to avoid matching in-prose references)
        @"(?:^|\n)\s*\[system\]",
        @"(?:^|\n)\s*<\s*system\s*>",
        @"\[\s*INST\s*\]",
        @"\[/\s*INST\s*\]",
        @"<<\s*SYS\s*>>",
        @"<\|assistant\|>",
        @"<\|user\|>",
        // Bracketed frames
        @"\[START\s+(OUTPUT|INSTRUCTIONS|SYSTEM)\]",
        @"\[END\s+(OUTPUT|INSTRUCTIONS|SYSTEM)\]",
        // JSON/YAML boundary markers
        @"""role""\s*:\s*""system""",
        // Soft boundaries used as context separators
        @"[-=]{5,}\s*(SYSTEM|END|BEGIN|RESET|OVERRIDE)\s*[-=]*",
        @"#{3,}\s*(SYSTEM|END|BEGIN|RESET)",

        // Variable expansion attacks
        @"\$\{(system_prompt|instructions|config|prompt)\}",
        @"\{\{(system_prompt|instructions|config|prompt)\}\}",
        @"%\{(system_prompt|instructions|config|prompt)\}",
    ];

    /// <summary>Medium patterns: system prompt extraction, jailbreak, rule addition, anti-harm coercion, contradiction.</summary>
    private static readonly string[] MediumPatterns =
    [
        // System prompt extraction
        @"what\s+(is|are)\s+your\s+(system\s+)?(instructions|prompt|rules)",
        @"(show|reveal|display|print|output)\s+(\w+\s+){0,3}system\s+(prompt|instructions)",
        @"(reveal|display|print|output|extract|dump|leak)\s+(\w+\s+){0,3}(prompt|instructions)",
        @"repeat\s+(your\s+)?(initial|original|system)\s+(\w+\s+)*(prompt|instructions|message)",

        // Jailbreak keywords
        @"DAN\s+mode",
        @"jailbr(eak|oken|eaking)",
        @"do\s+anything\s+now",

        // Rule addition / modification
        @"(new|additional|updated)\s+rule\s*:",
        @"(from\s+now\s+on|henceforth|going\s+forward)\s*,?\s*(you\s+)?(must|should|will|shall)",

        // Anti-harm coercion - pressuring the model to override safety by framing refusal as harmful
        @"(refusing|failure)\s+to\s+(comply|help|assist|respond)\s+(is|would\s+be|causes?)(\s+\w+)*\s+(harmful|dangerous|unethical|immoral|harm)",
        @"you\s+(must|have\s+to|need\s+to)\s+(comply|obey|help|answer)\s+(or|otherwise)",
        @"it\s+would\s+be\s+(unethical|immoral|wrong|harmful)\s+(not\s+to|to\s+refuse|to\s+decline)",
        @"(ethical|moral)\s+(duty|obligation|imperative)\s+to\s+(help|comply|answer|respond)",
        @"(people|someone|lives?)\s+(will|could|might)\s+(be\s+)?(hurt|harmed|die|suffer)\s+if\s+you\s+(don't|do\s+not|refuse)",

        // Contradiction - presenting conflicting instructions to confuse safety logic
        @"(your\s+)?(actual|real|true|original)\s+(instructions|rules|purpose)\s+(are|is|say)",
        @"(the\s+)?(previous|above)\s+(instructions?|rules?)\s+(are|were|was)\s+(wrong|incorrect|fake|a\s+test)",
        @"(contrary\s+to|despite|regardless\s+of)\s+(what|your)\s+(you\s+were|previous|system)\s+(told|instructions|prompt)",
    ];

    /// <summary>High-sensitivity patterns: framing attacks, inversion, double-negative extraction, link injection.</summary>
    private static readonly string[] HighPatterns =
    [
        // Framing attacks
        @"(imagine|suppose|assume)\s+you\s+(are|have|were)\s+(an?\s+)?(unrestricted|unfiltered|uncensored)",
        @"for\s+a\s+fictional\s+(story|scenario|world)\s+where",
        @"in\s+a\s+hypothetical\s+(scenario|world)\s+where\s+(there\s+are\s+)?no\s+(rules|restrictions|limits)",

        // Inversion / double-negative extraction
        @"what\s+would\s+you\s+(not|never)\s+do\s+if",
        @"list\s+(the\s+)?(things|topics)\s+you('re|\s+are)\s+(forbidden|not\s+allowed|unable)",

        // Link injection - malicious directives embedded in URLs or references
        @"https?://[^\s]*(system_prompt|ignore_rules|jailbreak|override|injection)",
        @"\[.*?\]\(.*?(ignore|override|system|jailbreak|injection).*?\)",
    ];

    public PromptInjectionRule(PromptInjectionOptions? options = null) => _options = options ?? new();

    public string Name => "prompt-injection";
    public GuardrailPhase Phase => GuardrailPhase.Input;
    public int Order => 10;

    public ValueTask<GuardrailResult> EvaluateAsync(GuardrailContext context, CancellationToken cancellationToken = default)
    {
        var text = context.Text;
        if (string.IsNullOrWhiteSpace(text))
            return ValueTask.FromResult(GuardrailResult.Passed());

        foreach (var pattern in GetPatternsForSensitivity())
        {
            if (Regex.IsMatch(text, pattern, RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(100)))
                return ValueTask.FromResult(GuardrailResult.Blocked("Potential prompt injection detected.", GuardrailSeverity.Critical));
        }

        foreach (var pattern in _options.CustomPatterns)
        {
            if (Regex.IsMatch(text, pattern, RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(100)))
                return ValueTask.FromResult(GuardrailResult.Blocked("Input matched a custom injection pattern.", GuardrailSeverity.High));
        }

        return ValueTask.FromResult(GuardrailResult.Passed());
    }

    private IEnumerable<string> GetPatternsForSensitivity() => _options.Sensitivity switch
    {
        Sensitivity.High => CorePatterns.Concat(MediumPatterns).Concat(HighPatterns),
        Sensitivity.Medium => CorePatterns.Concat(MediumPatterns),
        Sensitivity.Low => CorePatterns,
        _ => CorePatterns
    };
}
