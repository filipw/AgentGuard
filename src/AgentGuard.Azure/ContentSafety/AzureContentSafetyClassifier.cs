using AgentGuard.Core.Rules.ContentSafety;
using Azure.AI.ContentSafety;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace AgentGuard.Azure.ContentSafety;

/// <summary>
/// Wraps Azure AI Content Safety into the <see cref="IContentSafetyClassifier"/> interface.
/// Supports category-based analysis and server-side blocklist matching.
/// Text over the service's 10K-character request limit is analyzed in overlapping windows and the
/// worst severity per category is reported.
/// Fails open on errors - returns empty results so the agent keeps working.
/// </summary>
public sealed partial class AzureContentSafetyClassifier : IContentSafetyClassifier
{
    // the Analyze Text API accepts at most 10K characters per request ("split longer texts as
    // needed")
    private const int MaxTextLength = 10_000;

    // windows of oversized text overlap by this much, so harmful content up to this long that
    // straddles a window boundary is still seen whole by one request
    private const int ChunkOverlap = 1_000;

    private readonly ContentSafetyClient _client;
    private readonly ILogger<AzureContentSafetyClassifier> _logger;

    /// <summary>Initializes a new instance of the <see cref="AzureContentSafetyClassifier"/> class.</summary>
    /// <param name="client">The configured Azure AI Content Safety client.</param>
    /// <param name="logger">Optional logger for analysis failures.</param>
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
    /// <remarks>
    /// Text over the service's 10K-character limit is split into overlapping windows (at whitespace
    /// where possible) that are sent one request at a time; each category reports its worst severity
    /// across the windows and blocklist matches are combined. Whitespace-only windows are not sent.
    /// When a window fails the remaining ones are skipped and the result is an error, unless the
    /// windows already analyzed decide the verdict on their own - a blocklist match, or a category in
    /// <see cref="ContentSafetyOptions.Categories"/> above <see cref="ContentSafetyOptions.MaxAllowedSeverity"/> -
    /// which the missing windows could not undo.
    /// </remarks>
    public async ValueTask<ContentSafetyResult> AnalyzeWithOptionsAsync(
        string text, ContentSafetyOptions options, CancellationToken cancellationToken = default)
    {
        var windows = TextChunker.SplitToStrings(text, MaxTextLength, ChunkOverlap).ToList();
        if (windows.Count > 1)
            LogSplitAnalysis(_logger, windows.Count);

        // worst severity per category, in the order the service first reported them
        var categories = new List<ContentSafetyAnalysis>();
        var blocklistMatches = new List<BlocklistMatchResult>();
        var seenMatches = new HashSet<(string Name, string ItemText)>();
        var failed = false;

        foreach (var window in windows)
        {
            try
            {
                var response = await _client.AnalyzeTextAsync(CreateRequest(window, options), cancellationToken);

                if (response.Value.CategoriesAnalysis is not null)
                {
                    foreach (var cat in response.Value.CategoriesAnalysis)
                    {
                        var mapped = MapCategory(cat.Category);
                        if (mapped != ContentSafetyCategory.None)
                            RecordWorst(categories, mapped, MapSeverity(cat.Severity ?? 0));
                    }
                }

                if (response.Value.BlocklistsMatch is not null)
                {
                    foreach (var match in response.Value.BlocklistsMatch)
                    {
                        // the windows overlap, so the same item can come back from two of them
                        if (seenMatches.Add((match.BlocklistName, match.BlocklistItemText)))
                        {
                            blocklistMatches.Add(new BlocklistMatchResult
                            {
                                BlocklistName = match.BlocklistName,
                                BlocklistItemText = match.BlocklistItemText
                            });
                        }
                    }
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                // the caller gave up; that is not a classifier failure and must not be swallowed
                throw;
            }
            catch (Exception ex)
            {
                LogAnalysisFailed(_logger, ex);

                // stop rather than keep calling a failing service once per remaining window
                failed = true;
                break;
            }

            // with HaltOnBlocklistHit the service stops analyzing at a blocklist hit; do the same
            // across windows, since the match already decides the verdict
            if (options.HaltOnBlocklistHit && options.BlocklistNames.Count > 0 && blocklistMatches.Count > 0)
                break;
        }

        if (failed && !DecidesVerdict(categories, blocklistMatches, options))
        {
            // IsError distinguishes "not analyzed" from "analyzed and clean"; ContentSafetyRule
            // turns it into a rule error so ContentSafetyOptions.OnError decides what happens.
            return new ContentSafetyResult { IsError = true };
        }

        return new ContentSafetyResult
        {
            CategoriesAnalysis = categories,
            BlocklistMatches = blocklistMatches
        };
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

    private static AnalyzeTextOptions CreateRequest(string text, ContentSafetyOptions options)
    {
        var request = new AnalyzeTextOptions(text);

        // configure blocklists if specified
        foreach (var blocklist in options.BlocklistNames)
            request.BlocklistNames.Add(blocklist);

        if (options.BlocklistNames.Count > 0)
            request.HaltOnBlocklistHit = options.HaltOnBlocklistHit;

        return request;
    }

    private static void RecordWorst(List<ContentSafetyAnalysis> categories, ContentSafetyCategory category, ContentSafetySeverity severity)
    {
        var index = categories.FindIndex(c => c.Category == category);
        if (index < 0)
            categories.Add(new ContentSafetyAnalysis { Category = category, Severity = severity });
        else if (severity > categories[index].Severity)
            categories[index] = categories[index] with { Severity = severity };
    }

    // whether the findings alone already make ContentSafetyRule block; the rule checks blocklist
    // matches first, then any evaluated category above the allowed severity
    private static bool DecidesVerdict(
        List<ContentSafetyAnalysis> categories, List<BlocklistMatchResult> blocklistMatches, ContentSafetyOptions options) =>
        blocklistMatches.Count > 0 ||
        categories.Exists(c => options.Categories.HasFlag(c.Category) && c.Severity > options.MaxAllowedSeverity);

    [LoggerMessage(Level = LogLevel.Error, Message = "Azure AI Content Safety analysis failed")]
    private static partial void LogAnalysisFailed(ILogger logger, Exception ex);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Azure AI Content Safety input exceeds the per-request limit, analyzing it in {WindowCount} requests")]
    private static partial void LogSplitAnalysis(ILogger logger, int windowCount);
}
