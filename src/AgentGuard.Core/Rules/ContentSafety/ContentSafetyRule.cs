using AgentGuard.Core.Abstractions;

namespace AgentGuard.Core.Rules.ContentSafety;

public enum ContentSafetySeverity { Safe = 0, Low = 2, Medium = 4, High = 6 }

[Flags]
public enum ContentSafetyCategory { None = 0, Hate = 1, Violence = 2, SelfHarm = 4, Sexual = 8, All = Hate | Violence | SelfHarm | Sexual }

/// <summary>
/// Options for the content safety rule.
/// </summary>
public sealed class ContentSafetyOptions
{
    /// <summary>Maximum severity allowed before blocking. Default: Low.</summary>
    public ContentSafetySeverity MaxAllowedSeverity { get; init; } = ContentSafetySeverity.Low;

    /// <summary>Categories to evaluate. Default: All.</summary>
    public ContentSafetyCategory Categories { get; init; } = ContentSafetyCategory.All;

    /// <summary>
    /// Names of server-side blocklists to check against (Azure AI Content Safety feature).
    /// When populated, the classifier checks text against these named blocklists in addition to
    /// category-based analysis. Any blocklist match results in a block.
    /// </summary>
    public IList<string> BlocklistNames { get; init; } = [];

    /// <summary>
    /// When true, halt category analysis if a blocklist match is found (performance optimization).
    /// Only applies when <see cref="BlocklistNames"/> is non-empty. Default: false.
    /// </summary>
    public bool HaltOnBlocklistHit { get; init; }
}

/// <summary>Result of category-based content analysis.</summary>
public sealed record ContentSafetyAnalysis
{
    public ContentSafetyCategory Category { get; init; }
    public ContentSafetySeverity Severity { get; init; }
}

/// <summary>Result of a blocklist match.</summary>
public sealed record BlocklistMatchResult
{
    /// <summary>The name of the blocklist that matched.</summary>
    public required string BlocklistName { get; init; }

    /// <summary>The specific blocklist item that matched.</summary>
    public required string BlocklistItemText { get; init; }
}

/// <summary>Combined result from content safety analysis.</summary>
public sealed record ContentSafetyResult
{
    /// <summary>Category-based severity analysis results.</summary>
    public IReadOnlyList<ContentSafetyAnalysis> CategoriesAnalysis { get; init; } = [];

    /// <summary>Blocklist match results (empty if no blocklists configured or no matches).</summary>
    public IReadOnlyList<BlocklistMatchResult> BlocklistMatches { get; init; } = [];
}

/// <summary>
/// Classifies text for harmful content. Implementations may use cloud services (Azure AI Content Safety),
/// local models, or custom logic.
/// </summary>
public interface IContentSafetyClassifier
{
    /// <summary>
    /// Analyzes text for harmful content categories. Legacy method for backward compatibility.
    /// Default implementation delegates to <see cref="AnalyzeWithOptionsAsync"/>.
    /// </summary>
    ValueTask<IReadOnlyList<ContentSafetyAnalysis>> AnalyzeAsync(string text, CancellationToken cancellationToken = default);

    /// <summary>
    /// Analyzes text for harmful content with full options including blocklist support.
    /// Default implementation delegates to <see cref="AnalyzeAsync"/> and returns no blocklist matches.
    /// </summary>
    ValueTask<ContentSafetyResult> AnalyzeWithOptionsAsync(string text, ContentSafetyOptions options, CancellationToken cancellationToken = default)
        => DefaultAnalyzeWithOptionsAsync(this, text, options, cancellationToken);

    // Default interface implementation: delegates to AnalyzeAsync for backward compatibility
    private static async ValueTask<ContentSafetyResult> DefaultAnalyzeWithOptionsAsync(
        IContentSafetyClassifier self, string text, ContentSafetyOptions options, CancellationToken cancellationToken)
    {
        var categories = await self.AnalyzeAsync(text, cancellationToken);
        return new ContentSafetyResult { CategoriesAnalysis = categories };
    }
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

        var result = await _classifier.AnalyzeWithOptionsAsync(context.Text, _options, cancellationToken);

        // Check blocklist matches first
        if (result.BlocklistMatches.Count > 0)
        {
            var match = result.BlocklistMatches[0];
            return new GuardrailResult
            {
                IsBlocked = true,
                Reason = $"Content matched blocklist '{match.BlocklistName}': {match.BlocklistItemText}.",
                Severity = GuardrailSeverity.High,
                Metadata = new Dictionary<string, object>
                {
                    ["blocklistName"] = match.BlocklistName,
                    ["blocklistItemText"] = match.BlocklistItemText,
                    ["totalMatches"] = result.BlocklistMatches.Count
                }
            };
        }

        // Check category-based analysis
        foreach (var a in result.CategoriesAnalysis)
        {
            if (!_options.Categories.HasFlag(a.Category)) continue;
            if (a.Severity > _options.MaxAllowedSeverity)
                return GuardrailResult.Blocked($"Content safety violation: {a.Category} at severity {a.Severity}.", a.Severity switch
                { ContentSafetySeverity.High => GuardrailSeverity.Critical, ContentSafetySeverity.Medium => GuardrailSeverity.High, _ => GuardrailSeverity.Medium });
        }

        return GuardrailResult.Passed();
    }
}
