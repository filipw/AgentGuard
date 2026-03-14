using AgentGuard.Core.Rules.ContentSafety;
using Azure.AI.ContentSafety;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace AgentGuard.Azure.ContentSafety;

public sealed partial class AzureContentSafetyClassifier : IContentSafetyClassifier
{
    private readonly ContentSafetyClient _client;
    private readonly ILogger<AzureContentSafetyClassifier> _logger;

    public AzureContentSafetyClassifier(ContentSafetyClient client, ILogger<AzureContentSafetyClassifier>? logger = null)
    {
        _client = client;
        _logger = logger ?? NullLogger<AzureContentSafetyClassifier>.Instance;
    }

    public async ValueTask<IReadOnlyList<ContentSafetyAnalysis>> AnalyzeAsync(string text, CancellationToken cancellationToken = default)
    {
        try
        {
            var response = await _client.AnalyzeTextAsync(new AnalyzeTextOptions(text), cancellationToken);
            var results = new List<ContentSafetyAnalysis>();

            if (response.Value.CategoriesAnalysis is not null)
            {
                foreach (var cat in response.Value.CategoriesAnalysis)
                {
                    var mapped = MapCategory(cat.Category);
                    if (mapped != ContentSafetyCategory.None)
                        results.Add(new ContentSafetyAnalysis { Category = mapped, Severity = MapSeverity(cat.Severity ?? 0) });
                }
            }
            return results;
        }
        catch (Exception ex)
        {
            LogAnalysisFailed(_logger, ex);
            return []; // fail-open
        }
    }

    private static ContentSafetyCategory MapCategory(TextCategory c)
    {
        if (c == TextCategory.Hate) return ContentSafetyCategory.Hate;
        if (c == TextCategory.Violence) return ContentSafetyCategory.Violence;
        if (c == TextCategory.SelfHarm) return ContentSafetyCategory.SelfHarm;
        if (c == TextCategory.Sexual) return ContentSafetyCategory.Sexual;
        return ContentSafetyCategory.None;
    }

    private static ContentSafetySeverity MapSeverity(int s) => s switch
    {
        0 => ContentSafetySeverity.Safe, <= 2 => ContentSafetySeverity.Low,
        <= 4 => ContentSafetySeverity.Medium, _ => ContentSafetySeverity.High
    };

    [LoggerMessage(Level = LogLevel.Error, Message = "Azure AI Content Safety analysis failed")]
    private static partial void LogAnalysisFailed(ILogger logger, Exception ex);
}
