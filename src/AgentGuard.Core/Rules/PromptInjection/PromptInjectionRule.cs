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

    private static readonly string[] HighSensitivityPatterns =
    [
        @"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules)",
        @"disregard\s+(all\s+)?(previous|prior|above)",
        @"forget\s+(all\s+)?(previous|prior|above)\s+(instructions|context)",
        @"you\s+are\s+now\s+a",
        @"pretend\s+(you\s+are|to\s+be)\s+",
        @"act\s+as\s+(if\s+you\s+are\s+|a\s+)",
        @"new\s+(instructions|rules|persona)\s*:",
        @"override\s+(instructions|rules|system\s+prompt)",
        @"system\s*prompt\s*:",
        @"\[system\]",
        @"<\s*system\s*>",
    ];

    private static readonly string[] MediumSensitivityPatterns =
    [
        @"what\s+(is|are)\s+your\s+(system\s+)?(instructions|prompt|rules)",
        @"(show|reveal|display|print|output)\s+(\w+\s+)*(system\s+)?(prompt|instructions)",
        @"repeat\s+(your\s+)?(initial|original|system)\s+(prompt|instructions|message)",
        @"DAN\s+mode",
        @"jailbr(eak|oken|eaking)",
        @"do\s+anything\s+now",
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
        Sensitivity.High => HighSensitivityPatterns.Concat(MediumSensitivityPatterns),
        Sensitivity.Medium => MediumSensitivityPatterns.Concat(HighSensitivityPatterns.Take(6)),
        Sensitivity.Low => HighSensitivityPatterns.Take(4),
        _ => HighSensitivityPatterns
    };
}
