using AgentGuard.Core.Abstractions;

namespace AgentGuard.Core.Rules.ContentSafety;

public enum ContentSafetySeverity { Safe = 0, Low = 2, Medium = 4, High = 6 }

[Flags]
public enum ContentSafetyCategory { None = 0, Hate = 1, Violence = 2, SelfHarm = 4, Sexual = 8, All = Hate | Violence | SelfHarm | Sexual }

public sealed class ContentSafetyOptions
{
    public ContentSafetySeverity MaxAllowedSeverity { get; init; } = ContentSafetySeverity.Low;
    public ContentSafetyCategory Categories { get; init; } = ContentSafetyCategory.All;
}

public sealed record ContentSafetyAnalysis { public ContentSafetyCategory Category { get; init; } public ContentSafetySeverity Severity { get; init; } }

public interface IContentSafetyClassifier
{
    ValueTask<IReadOnlyList<ContentSafetyAnalysis>> AnalyzeAsync(string text, CancellationToken cancellationToken = default);
}

public sealed class ContentSafetyRule : IGuardrailRule
{
    private readonly ContentSafetyOptions _options;
    private readonly IContentSafetyClassifier? _classifier;

    public ContentSafetyRule(ContentSafetyOptions? options = null, IContentSafetyClassifier? classifier = null)
    { _options = options ?? new(); _classifier = classifier; }

    public string Name => "content-safety";
    public GuardrailPhase Phase => GuardrailPhase.Both;
    public int Order => 50;

    public async ValueTask<GuardrailResult> EvaluateAsync(GuardrailContext context, CancellationToken cancellationToken = default)
    {
        if (_classifier is null) return GuardrailResult.Passed();
        var analyses = await _classifier.AnalyzeAsync(context.Text, cancellationToken);
        foreach (var a in analyses)
        {
            if (!_options.Categories.HasFlag(a.Category)) continue;
            if (a.Severity > _options.MaxAllowedSeverity)
                return GuardrailResult.Blocked($"Content safety violation: {a.Category} at severity {a.Severity}.", a.Severity switch
                { ContentSafetySeverity.High => GuardrailSeverity.Critical, ContentSafetySeverity.Medium => GuardrailSeverity.High, _ => GuardrailSeverity.Medium });
        }
        return GuardrailResult.Passed();
    }
}
