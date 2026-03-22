using AgentGuard.Core.Rules.ContentSafety;
using Azure.AI.ContentSafety;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace AgentGuard.Azure.ContentSafety;

/// <summary>
/// Wraps Azure AI Content Safety into the <see cref="IContentSafetyClassifier"/> interface.
/// Supports category-based analysis and server-side blocklist matching.
/// Fails open on errors - returns empty results so the agent keeps working.
/// </summary>
public sealed partial class AzureContentSafetyClassifier : IContentSafetyClassifier
{
    private readonly ContentSafetyClient _client;
    private readonly ILogger<AzureContentSafetyClassifier> _logger;

    public AzureContentSafetyClassifier(ContentSafetyClient client, ILogger<AzureContentSafetyClassifier>? logger = null)
    {
        _client = client;
        _logger = logger ?? NullLogger<AzureContentSafetyClassifier>.Instance;
    }

    /// <inheritdoc />
    public async ValueTask<IReadOnlyList<ContentSafetyAnalysis>> AnalyzeAsync(string text, CancellationToken cancellationToken = default)
    {
        var result = await AnalyzeWithOptionsAsync(text, new ContentSafetyOptions(), cancellationToken);
        return result.CategoriesAnalysis;
    }

    /// <inheritdoc />
    public async ValueTask<ContentSafetyResult> AnalyzeWithOptionsAsync(
        string text, ContentSafetyOptions options, CancellationToken cancellationToken = default)
    {
        try
        {
            var request = new AnalyzeTextOptions(text);

            // Configure blocklists if specified
            foreach (var blocklist in options.BlocklistNames)
                request.BlocklistNames.Add(blocklist);

            if (options.BlocklistNames.Count > 0)
                request.HaltOnBlocklistHit = options.HaltOnBlocklistHit;

            var response = await _client.AnalyzeTextAsync(request, cancellationToken);

            // Map category analysis
            var categories = new List<ContentSafetyAnalysis>();
            if (response.Value.CategoriesAnalysis is not null)
            {
                foreach (var cat in response.Value.CategoriesAnalysis)
                {
                    var mapped = MapCategory(cat.Category);
                    if (mapped != ContentSafetyCategory.None)
                        categories.Add(new ContentSafetyAnalysis { Category = mapped, Severity = MapSeverity(cat.Severity ?? 0) });
                }
            }

            // Map blocklist matches
            var blocklistMatches = new List<BlocklistMatchResult>();
            if (response.Value.BlocklistsMatch is not null)
            {
                foreach (var match in response.Value.BlocklistsMatch)
                {
                    blocklistMatches.Add(new BlocklistMatchResult
                    {
                        BlocklistName = match.BlocklistName,
                        BlocklistItemText = match.BlocklistItemText
                    });
                }
            }

            return new ContentSafetyResult
            {
                CategoriesAnalysis = categories,
                BlocklistMatches = blocklistMatches
            };
        }
        catch (Exception ex)
        {
            LogAnalysisFailed(_logger, ex);
            return new ContentSafetyResult(); // fail-open
        }
    }

    internal static ContentSafetyCategory MapCategory(TextCategory c)
    {
        if (c == TextCategory.Hate) return ContentSafetyCategory.Hate;
        if (c == TextCategory.Violence) return ContentSafetyCategory.Violence;
        if (c == TextCategory.SelfHarm) return ContentSafetyCategory.SelfHarm;
        if (c == TextCategory.Sexual) return ContentSafetyCategory.Sexual;
        return ContentSafetyCategory.None;
    }

    internal static ContentSafetySeverity MapSeverity(int s) => s switch
    {
        0 => ContentSafetySeverity.Safe, <= 2 => ContentSafetySeverity.Low,
        <= 4 => ContentSafetySeverity.Medium, _ => ContentSafetySeverity.High
    };

    [LoggerMessage(Level = LogLevel.Error, Message = "Azure AI Content Safety analysis failed")]
    private static partial void LogAnalysisFailed(ILogger logger, Exception ex);
}
