using AgentGuard.Core.Rules.ContentSafety;
using Azure.AI.ContentSafety;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace AgentGuard.Azure.ContentSafety;

public sealed class AzureContentSafetyClassifier : IContentSafetyClassifier
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
            _logger.LogError(ex, "Azure AI Content Safety analysis failed");
            return []; // fail-open
        }
    }

    private static ContentSafetyCategory MapCategory(TextCategory c) => c switch
    {
        TextCategory.Hate => ContentSafetyCategory.Hate,
        TextCategory.Violence => ContentSafetyCategory.Violence,
        TextCategory.SelfHarm => ContentSafetyCategory.SelfHarm,
        TextCategory.Sexual => ContentSafetyCategory.Sexual,
        _ => ContentSafetyCategory.None
    };

    private static ContentSafetySeverity MapSeverity(int s) => s switch
    {
        0 => ContentSafetySeverity.Safe, <= 2 => ContentSafetySeverity.Low,
        <= 4 => ContentSafetySeverity.Medium, _ => ContentSafetySeverity.High
    };
}
