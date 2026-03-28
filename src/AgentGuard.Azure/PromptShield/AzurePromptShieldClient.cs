using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace AgentGuard.Azure.PromptShield;

/// <summary>
/// Result from the Azure Prompt Shield API.
/// </summary>
public sealed record PromptShieldResult
{
    /// <summary>Whether an attack was detected in the user prompt.</summary>
    public bool UserPromptAttackDetected { get; init; }

    /// <summary>Per-document attack detection results.</summary>
    public IReadOnlyList<bool> DocumentAttacksDetected { get; init; } = [];
}

/// <summary>
/// Lightweight HTTP client for the Azure Content Safety Prompt Shield API
/// (<c>/contentsafety/text:shieldPrompt</c>).
/// Detects user prompt attacks (jailbreaks) and document attacks (indirect injection).
/// Fails open on errors.
/// </summary>
public sealed partial class AzurePromptShieldClient : IDisposable
{
    private const string ApiVersion = "2024-09-01";

    private readonly HttpClient _httpClient;
    private readonly bool _ownsHttpClient;
    private readonly ILogger<AzurePromptShieldClient> _logger;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    /// <summary>
    /// Creates a new client targeting the specified Azure Content Safety endpoint.
    /// </summary>
    /// <param name="endpoint">The Azure Content Safety endpoint URL (e.g. https://my-resource.cognitiveservices.azure.com/).</param>
    /// <param name="apiKey">The API key for the Content Safety resource.</param>
    /// <param name="httpClient">Optional pre-configured HttpClient. If null, a new one is created.</param>
    /// <param name="logger">Optional logger.</param>
    public AzurePromptShieldClient(
        string endpoint, string apiKey,
        HttpClient? httpClient = null,
        ILogger<AzurePromptShieldClient>? logger = null)
    {
        _logger = logger ?? NullLogger<AzurePromptShieldClient>.Instance;

        if (httpClient is not null)
        {
            _httpClient = httpClient;
            _ownsHttpClient = false;
        }
        else
        {
            _httpClient = new HttpClient();
            _ownsHttpClient = true;
        }

        var baseUrl = endpoint.TrimEnd('/');
        _httpClient.BaseAddress ??= new Uri(baseUrl);
        _httpClient.DefaultRequestHeaders.TryAddWithoutValidation("Ocp-Apim-Subscription-Key", apiKey);
    }

    /// <summary>
    /// Analyzes a user prompt for prompt injection attacks.
    /// </summary>
    public ValueTask<PromptShieldResult> AnalyzeUserPromptAsync(
        string userPrompt, CancellationToken cancellationToken = default)
        => AnalyzeAsync(userPrompt, null, cancellationToken);

    /// <summary>
    /// Analyzes a user prompt and documents for prompt injection and indirect injection attacks.
    /// </summary>
    public async ValueTask<PromptShieldResult> AnalyzeAsync(
        string userPrompt, IReadOnlyList<string>? documents = null,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var request = new ShieldPromptRequest
            {
                UserPrompt = userPrompt,
                Documents = documents ?? []
            };

            var url = $"/contentsafety/text:shieldPrompt?api-version={ApiVersion}";
            var response = await _httpClient.PostAsJsonAsync(url, request, JsonOptions, cancellationToken);
            response.EnsureSuccessStatusCode();

            var result = await response.Content.ReadFromJsonAsync<ShieldPromptResponse>(JsonOptions, cancellationToken);
            if (result is null)
                return new PromptShieldResult();

            return new PromptShieldResult
            {
                UserPromptAttackDetected = result.UserPromptAnalysis?.AttackDetected ?? false,
                DocumentAttacksDetected = result.DocumentsAnalysis?
                    .Select(d => d.AttackDetected)
                    .ToList() ?? []
            };
        }
        catch (Exception ex)
        {
            LogAnalysisFailed(_logger, ex);
            return new PromptShieldResult(); // fail-open
        }
    }

    public void Dispose()
    {
        if (_ownsHttpClient)
            _httpClient.Dispose();
    }

    [LoggerMessage(Level = LogLevel.Error, Message = "Azure Prompt Shield analysis failed")]
    private static partial void LogAnalysisFailed(ILogger logger, Exception ex);

    // --- JSON DTOs ---

    private sealed class ShieldPromptRequest
    {
        public string UserPrompt { get; init; } = "";
        public IReadOnlyList<string> Documents { get; init; } = [];
    }

    private sealed class ShieldPromptResponse
    {
        public AnalysisResult? UserPromptAnalysis { get; init; }
        public List<AnalysisResult>? DocumentsAnalysis { get; init; }
    }

    private sealed class AnalysisResult
    {
        public bool AttackDetected { get; init; }
    }
}
