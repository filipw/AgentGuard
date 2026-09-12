using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace AgentGuard.Azure.ProtectedMaterial;

/// <summary>
/// Whether the detected material is text or code.
/// </summary>
public enum ProtectedMaterialType
{
    /// <summary>Protected text content (song lyrics, articles, recipes, etc.).</summary>
    Text,
    /// <summary>Protected code from GitHub repositories.</summary>
    Code
}

/// <summary>
/// A citation identifying the source of detected protected code.
/// </summary>
public sealed record CodeCitation
{
    /// <summary>The license type associated with the detected code (e.g. "MIT", "GPL-3.0", "NOASSERTION").</summary>
    public string License { get; init; } = "";

    /// <summary>GitHub repository URLs where the protected code was found.</summary>
    public IReadOnlyList<string> SourceUrls { get; init; } = [];
}

/// <summary>
/// Result from the Azure Protected Material detection APIs.
/// </summary>
public sealed record ProtectedMaterialResult
{
    /// <summary>Whether protected material was detected.</summary>
    public bool Detected { get; init; }

    /// <summary>The type of protected material that was analyzed.</summary>
    public ProtectedMaterialType MaterialType { get; init; }

    /// <summary>Code citations, if the analysis was for code and matches were found. Empty for text analysis.</summary>
    public IReadOnlyList<CodeCitation> CodeCitations { get; init; } = [];

    /// <summary>
    /// True when the API call failed (error, timeout, retry exhaustion).
    /// The result is a fail-open default, not an actual classification.
    /// </summary>
    public bool IsError { get; init; }
}

/// <summary>
/// Lightweight HTTP client for the Azure Content Safety Protected Material detection APIs.
/// <list type="bullet">
///   <item><c>/contentsafety/text:detectProtectedMaterial</c> - detects known copyrighted text (lyrics, articles, recipes)</item>
///   <item><c>/contentsafety/text:detectProtectedMaterialForCode</c> - detects code from GitHub repositories with license info</item>
/// </list>
/// No C# SDK support exists for these APIs - REST only.
/// Fails open on errors.
/// </summary>
public sealed partial class AzureProtectedMaterialClient : IDisposable
{
    private const string TextApiVersion = "2024-09-01";
    private const string CodeApiVersion = "2024-09-15-preview";

    private readonly HttpClient _httpClient;
    private readonly bool _ownsHttpClient;
    private readonly string _endpoint;
    private readonly string _apiKey;

    private static readonly TimeSpan DefaultRetryDelay = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan MaxRetryDelay = TimeSpan.FromSeconds(10);
    private readonly ILogger<AzureProtectedMaterialClient> _logger;

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
    public AzureProtectedMaterialClient(
        string endpoint, string apiKey,
        HttpClient? httpClient = null,
        ILogger<AzureProtectedMaterialClient>? logger = null)
    {
        _logger = logger ?? NullLogger<AzureProtectedMaterialClient>.Instance;

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

        // The endpoint and key are held per instance and applied per request rather than written
        // onto the HttpClient. Mutating a client that came from IHttpClientFactory is shared state:
        // BaseAddress ??= silently ignored the configured endpoint when one was already set, and
        // TryAddWithoutValidation appended a second subscription-key header for every additional
        // instance built over the same client.
        _endpoint = endpoint.TrimEnd('/');
        _apiKey = apiKey;
    }

    /// <summary>
    /// Analyzes text for protected material (song lyrics, articles, recipes, known web content).
    /// Meant to be run on LLM completions, not user prompts.
    /// </summary>
    public async ValueTask<ProtectedMaterialResult> AnalyzeTextAsync(
        string text, CancellationToken cancellationToken = default)
    {
        try
        {
            var request = new TextRequest { Text = text };
            var url = $"/contentsafety/text:detectProtectedMaterial?api-version={TextApiVersion}";
            using var response = await SendWithRetryAsync(url, request, cancellationToken);
            response.EnsureSuccessStatusCode();

            var result = await response.Content.ReadFromJsonAsync<ProtectedMaterialResponse>(JsonOptions, cancellationToken);

            return new ProtectedMaterialResult
            {
                Detected = result?.ProtectedMaterialAnalysis?.Detected ?? false,
                MaterialType = ProtectedMaterialType.Text
            };
        }
        catch (Exception ex)
        {
            LogTextAnalysisFailed(_logger, ex);
            return new ProtectedMaterialResult { MaterialType = ProtectedMaterialType.Text, IsError = true }; // fail-open
        }
    }

    /// <summary>
    /// Analyzes code for protected material from GitHub repositories.
    /// Returns license information and source URLs when matches are found.
    /// Meant to be run on LLM completions, not user prompts.
    /// </summary>
    public async ValueTask<ProtectedMaterialResult> AnalyzeCodeAsync(
        string code, CancellationToken cancellationToken = default)
    {
        try
        {
            var request = new CodeRequest { Code = code };
            var url = $"/contentsafety/text:detectProtectedMaterialForCode?api-version={CodeApiVersion}";
            using var response = await SendWithRetryAsync(url, request, cancellationToken);
            response.EnsureSuccessStatusCode();

            var result = await response.Content.ReadFromJsonAsync<ProtectedMaterialResponse>(JsonOptions, cancellationToken);
            var analysis = result?.ProtectedMaterialAnalysis;

            return new ProtectedMaterialResult
            {
                Detected = analysis?.Detected ?? false,
                MaterialType = ProtectedMaterialType.Code,
                CodeCitations = analysis?.CodeCitations?
                    .Select(c => new CodeCitation
                    {
                        License = c.License ?? "",
                        SourceUrls = c.SourceUrls ?? []
                    })
                    .ToList() ?? []
            };
        }
        catch (Exception ex)
        {
            LogCodeAnalysisFailed(_logger, ex);
            return new ProtectedMaterialResult { MaterialType = ProtectedMaterialType.Code, IsError = true }; // fail-open
        }
    }

    /// <summary>
    /// POSTs <paramref name="request"/>, retrying on 429 up to <c>maxRetries</c> times.
    /// </summary>
    /// <remarks>
    /// Discarded 429 responses are disposed rather than leaked, and the server's Retry-After is
    /// clamped to <see cref="MaxRetryDelay"/> so a misconfigured or hostile value cannot park a
    /// guarded request for minutes.
    /// </remarks>
    private async Task<HttpResponseMessage> SendWithRetryAsync<TRequest>(
        string path, TRequest request, CancellationToken cancellationToken)
    {
        const int maxRetries = 3;
        HttpResponseMessage? response = null;

        for (var attempt = 0; attempt < maxRetries; attempt++)
        {
            using var message = new HttpRequestMessage(HttpMethod.Post, _endpoint + path)
            {
                Content = JsonContent.Create(request, options: JsonOptions)
            };
            message.Headers.TryAddWithoutValidation("Ocp-Apim-Subscription-Key", _apiKey);

            response = await _httpClient.SendAsync(message, cancellationToken);

            if ((int)response.StatusCode != 429)
                return response;

            if (attempt == maxRetries - 1)
            {
                LogRetryExhausted(_logger, maxRetries);
                return response; // will fail via EnsureSuccessStatusCode -> catch -> fail-open
            }

            var retryAfter = response.Headers.RetryAfter?.Delta ?? DefaultRetryDelay;
            if (retryAfter > MaxRetryDelay)
                retryAfter = MaxRetryDelay;
            if (retryAfter < TimeSpan.Zero)
                retryAfter = DefaultRetryDelay;

            // this response is being thrown away; its content stream has to go with it
            response.Dispose();
            response = null;

            LogRateLimited(_logger, attempt + 1, maxRetries, retryAfter);
            await Task.Delay(retryAfter, cancellationToken);
        }

        // unreachable: the loop either returns or throws
        throw new InvalidOperationException("retry loop completed without a response");
    }

    /// <summary>Disposes the <see cref="HttpClient"/> when this instance created it.</summary>
    public void Dispose()
    {
        if (_ownsHttpClient)
            _httpClient.Dispose();
    }

    [LoggerMessage(Level = LogLevel.Error, Message = "Azure Protected Material text analysis failed")]
    private static partial void LogTextAnalysisFailed(ILogger logger, Exception ex);

    [LoggerMessage(Level = LogLevel.Error, Message = "Azure Protected Material code analysis failed")]
    private static partial void LogCodeAnalysisFailed(ILogger logger, Exception ex);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Azure Protected Material rate limited, retry {Attempt}/{MaxRetries} after {RetryAfter}")]
    private static partial void LogRateLimited(ILogger logger, int attempt, int maxRetries, TimeSpan retryAfter);

    [LoggerMessage(Level = LogLevel.Error, Message = "Azure Protected Material rate limit retries exhausted after {MaxRetries} attempts - failing open")]
    private static partial void LogRetryExhausted(ILogger logger, int maxRetries);

    // --- JSON DTOs ---

    private sealed class TextRequest
    {
        public string Text { get; init; } = "";
    }

    private sealed class CodeRequest
    {
        public string Code { get; init; } = "";
    }

    private sealed class ProtectedMaterialResponse
    {
        public ProtectedMaterialAnalysisDto? ProtectedMaterialAnalysis { get; init; }
    }

    private sealed class ProtectedMaterialAnalysisDto
    {
        public bool Detected { get; init; }
        public List<CodeCitationDto>? CodeCitations { get; init; }
    }

    private sealed class CodeCitationDto
    {
        public string? License { get; init; }
        public List<string>? SourceUrls { get; init; }
    }
}
