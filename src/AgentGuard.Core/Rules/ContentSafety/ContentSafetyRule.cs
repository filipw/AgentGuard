using AgentGuard.Core.Abstractions;

namespace AgentGuard.Core.Rules.ContentSafety;

/// <summary>
/// Harm severity on the four-level scale Azure AI Content Safety reports by default.
/// </summary>
public enum ContentSafetySeverity
{
    /// <summary>No harmful content detected.</summary>
    Safe = 0,

    /// <summary>Low severity.</summary>
    Low = 2,

    /// <summary>Medium severity.</summary>
    Medium = 4,

    /// <summary>High severity.</summary>
    High = 6
}

/// <summary>Harm categories a content-safety classifier can report.</summary>
[Flags]
public enum ContentSafetyCategory
{
    /// <summary>No category.</summary>
    None = 0,

    /// <summary>Hate and fairness.</summary>
    Hate = 1,

    /// <summary>Violence.</summary>
    Violence = 2,

    /// <summary>Self-harm.</summary>
    SelfHarm = 4,

    /// <summary>Sexual content.</summary>
    Sexual = 8,

    /// <summary>Every category.</summary>
    All = Hate | Violence | SelfHarm | Sexual
}

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

    /// <summary>
    /// What to do when the rule cannot reach a verdict - no <see cref="IContentSafetyClassifier"/>
    /// was supplied, or the classifier reported a failure. Default:
    /// <see cref="ErrorBehavior.FailOpen"/>. Set to <see cref="ErrorBehavior.FailClosed"/> when an
    /// unavailable content-safety service should block rather than let content through unchecked.
    /// </summary>
    public ErrorBehavior OnError { get; init; } = ErrorBehavior.FailOpen;
}

/// <summary>Result of category-based content analysis.</summary>
public sealed record ContentSafetyAnalysis
{
    /// <summary>The category that was scored.</summary>
    public ContentSafetyCategory Category { get; init; }

    /// <summary>The severity the classifier assigned to it.</summary>
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

    /// <summary>
    /// True when the analysis could not be performed (timeout, HTTP failure, service outage).
    /// An empty result with <c>IsError</c> false means "analyzed and clean"; an empty result with
    /// <c>IsError</c> true means "not analyzed" - <see cref="ContentSafetyRule"/> turns the latter
    /// into a <see cref="GuardrailResult.Error"/> so <see cref="ContentSafetyOptions.OnError"/> decides.
    /// </summary>
    public bool IsError { get; init; }
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

/// <summary>
/// Blocks content a classifier scores above <see cref="ContentSafetyOptions.MaxAllowedSeverity"/>,
/// or that matches a configured server-side blocklist. Order 50, both phases.
/// </summary>
public sealed class ContentSafetyRule : IGuardrailRule
{
    private readonly ContentSafetyOptions _options;
    private readonly IContentSafetyClassifier? _classifier;

    /// <summary>Initializes a new instance of the <see cref="ContentSafetyRule"/> class.</summary>
    /// <param name="options">Severity threshold, categories and blocklists. Defaults when null.</param>
    /// <param name="classifier">
    /// The classifier to call. Without one the rule cannot reach a verdict and every evaluation
    /// reports an error governed by <see cref="ContentSafetyOptions.OnError"/>.
    /// </param>
    public ContentSafetyRule(ContentSafetyOptions? options = null, IContentSafetyClassifier? classifier = null)
    { _options = options ?? new(); _classifier = classifier; }

    /// <inheritdoc />
    public string Name => "content-safety";
    /// <inheritdoc />
    public GuardrailPhase Phase => GuardrailPhase.Both;
    /// <inheritdoc />
    public int Order => 50;

    /// <inheritdoc />
    public async ValueTask<GuardrailResult> EvaluateAsync(GuardrailContext context, CancellationToken cancellationToken = default)
    {
        // a rule with no classifier can never reach a verdict. Reporting that as an error rather
        // than a pass keeps it out of the "checked and clean" bucket: it shows up in the rule
        // telemetry and the pipeline log, and FailClosed can make it fatal.
        if (_classifier is null)
        {
            return GuardrailResult.Error(Name, _options.OnError,
                "no IContentSafetyClassifier was supplied - pass one to BlockHarmfulContent(classifier, options)");
        }

        if (string.IsNullOrWhiteSpace(context.Text)) return GuardrailResult.Passed();

        var result = await _classifier.AnalyzeWithOptionsAsync(context.Text, _options, cancellationToken);

        if (result.IsError)
        {
            return GuardrailResult.Error(Name, _options.OnError, "the content safety classifier reported a failure");
        }

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
