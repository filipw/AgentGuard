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

    /// <summary>
    /// True when the API call failed (error, timeout, retry exhaustion).
    /// The result is a fail-open default, not an actual classification.
    /// </summary>
    public bool IsError { get; init; }
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
            var response = await SendWithRetryAsync(url, request, cancellationToken);
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
            return new PromptShieldResult { IsError = true }; // fail-open
        }
    }

    public void Dispose()
    {
        if (_ownsHttpClient)
            _httpClient.Dispose();
    }

    private async Task<HttpResponseMessage> SendWithRetryAsync<TRequest>(
        string url, TRequest request, CancellationToken cancellationToken)
    {
        const int maxRetries = 3;
        for (var attempt = 0; attempt < maxRetries; attempt++)
        {
            var response = await _httpClient.PostAsJsonAsync(url, request, JsonOptions, cancellationToken);
            if ((int)response.StatusCode != 429)
                return response;

            if (attempt == maxRetries - 1)
            {
                LogRetryExhausted(_logger, maxRetries);
                return response; // will fail via EnsureSuccessStatusCode → catch → fail-open
            }

            var retryAfter = response.Headers.RetryAfter?.Delta ?? TimeSpan.FromSeconds(1);
            LogRateLimited(_logger, attempt + 1, maxRetries, retryAfter);
            await Task.Delay(retryAfter, cancellationToken);
        }

        throw new InvalidOperationException();
    }

    [LoggerMessage(Level = LogLevel.Error, Message = "Azure Prompt Shield analysis failed")]
    private static partial void LogAnalysisFailed(ILogger logger, Exception ex);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Azure Prompt Shield rate limited, retry {Attempt}/{MaxRetries} after {RetryAfter}")]
    private static partial void LogRateLimited(ILogger logger, int attempt, int maxRetries, TimeSpan retryAfter);

    [LoggerMessage(Level = LogLevel.Error, Message = "Azure Prompt Shield rate limit retries exhausted after {MaxRetries} attempts — failing open")]
    private static partial void LogRetryExhausted(ILogger logger, int maxRetries);

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
