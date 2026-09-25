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
    /// True when an API call failed (error, timeout, retry exhaustion) and none of the calls that did
    /// complete detected protected material. The result is a fail-open default, not an actual
    /// classification. Text below the service's minimum length is not an error: it is not sent, and
    /// comes back as not detected.
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
/// Both APIs accept 110 to 10K characters per request: shorter input is not sent, longer input is
/// analyzed in overlapping windows.
/// Fails open on errors.
/// </summary>
public sealed partial class AzureProtectedMaterialClient : IDisposable
{
    private const string TextApiVersion = "2024-09-01";
    private const string CodeApiVersion = "2024-09-15-preview";

    // the documented per-request limits of both detection APIs
    private const int MaxTextLength = 10_000;
    private const int MinTextLength = 110;

    // windows of oversized input overlap by this much, comfortably more than the spans the service
    // flags (lyrics over 11 words, news or web excerpts over 200 characters), so a match straddling a
    // window boundary is still seen whole by one request
    private const int ChunkOverlap = 1_000;

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
    /// <remarks>
    /// Text shorter than the service's 110-character minimum is not sent and comes back as not
    /// detected - too short to match protected material, and not an error. Text over the 10K-character
    /// limit is analyzed in overlapping windows, one request at a time, until one of them reports a
    /// match. When a request fails the remaining ones are skipped and the result is an error.
    /// </remarks>
    public async ValueTask<ProtectedMaterialResult> AnalyzeTextAsync(
        string text, CancellationToken cancellationToken = default)
    {
        var windows = Windows(text, ProtectedMaterialType.Text);
        var url = $"/contentsafety/text:detectProtectedMaterial?api-version={TextApiVersion}";

        foreach (var window in windows)
        {
            try
            {
                var result = await PostAsync(url, new TextRequest { Text = window }, cancellationToken);

                // a match is the whole answer; the remaining windows cannot add to it
                if (result?.ProtectedMaterialAnalysis?.Detected == true)
                    return new ProtectedMaterialResult { Detected = true, MaterialType = ProtectedMaterialType.Text };
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                // the caller gave up; that is not an analysis failure and must not become a fail-open pass
                throw;
            }
            catch (Exception ex)
            {
                LogTextAnalysisFailed(_logger, ex);
                return new ProtectedMaterialResult { MaterialType = ProtectedMaterialType.Text, IsError = true }; // fail-open
            }
        }

        return new ProtectedMaterialResult { MaterialType = ProtectedMaterialType.Text };
    }

    /// <summary>
    /// Analyzes code for protected material from GitHub repositories.
    /// Returns license information and source URLs when matches are found.
    /// Meant to be run on LLM completions, not user prompts.
    /// </summary>
    /// <remarks>
    /// Code shorter than the service's 110-character minimum is not sent and comes back as not
    /// detected. Code over the 10K-character limit is analyzed in overlapping windows (split at line
    /// breaks where possible), one request at a time, and their citations are combined. When a request
    /// fails the remaining ones are skipped, and the result is an error unless a match was already found.
    /// </remarks>
    public async ValueTask<ProtectedMaterialResult> AnalyzeCodeAsync(
        string code, CancellationToken cancellationToken = default)
    {
        var windows = Windows(code, ProtectedMaterialType.Code);
        var url = $"/contentsafety/text:detectProtectedMaterialForCode?api-version={CodeApiVersion}";

        var detected = false;
        var citations = new List<CodeCitation>();
        var seenCitations = new HashSet<string>(StringComparer.Ordinal);

        foreach (var window in windows)
        {
            try
            {
                var result = await PostAsync(url, new CodeRequest { Code = window }, cancellationToken);
                var analysis = result?.ProtectedMaterialAnalysis;

                if (analysis?.Detected == true)
                    detected = true;

                foreach (var citation in analysis?.CodeCitations ?? [])
                {
                    var sourceUrls = citation.SourceUrls ?? [];

                    // the windows overlap, so the same citation can come back from two of them
                    if (seenCitations.Add(citation.License + "\n" + string.Join("\n", sourceUrls)))
                        citations.Add(new CodeCitation { License = citation.License ?? "", SourceUrls = sourceUrls });
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                // the caller gave up; that is not an analysis failure and must not become a fail-open pass
                throw;
            }
            catch (Exception ex)
            {
                LogCodeAnalysisFailed(_logger, ex);

                // a match found before the failure decides the verdict whatever the rest would have said
                if (!detected)
                    return new ProtectedMaterialResult { MaterialType = ProtectedMaterialType.Code, IsError = true }; // fail-open

                break;
            }
        }

        return new ProtectedMaterialResult
        {
            Detected = detected,
            MaterialType = ProtectedMaterialType.Code,
            CodeCitations = citations
        };
    }

    /// <summary>Disposes the <see cref="HttpClient"/> when this instance created it.</summary>
    public void Dispose()
    {
        if (_ownsHttpClient)
            _httpClient.Dispose();
    }

    /// <summary>
    /// The request-sized windows of <paramref name="input"/> worth sending: at most 10K characters
    /// each, and none below the 110-character minimum the service rejects.
    /// </summary>
    private List<string> Windows(string? input, ProtectedMaterialType materialType)
    {
        var windows = TextChunker.SplitToStrings(input, MaxTextLength, ChunkOverlap)
            .Where(window => TextChunker.HasAtLeastTextElements(window, MinTextLength))
            .ToList();

        if (windows.Count == 0)
            LogBelowMinimumLength(_logger, materialType, MinTextLength);
        else if (windows.Count > 1)
            LogSplitAnalysis(_logger, materialType, windows.Count);

        return windows;
    }

    private async Task<ProtectedMaterialResponse?> PostAsync<TRequest>(
        string path, TRequest request, CancellationToken cancellationToken)
    {
        using var response = await SendWithRetryAsync(path, request, cancellationToken);
        response.EnsureSuccessStatusCode();

        return await response.Content.ReadFromJsonAsync<ProtectedMaterialResponse>(JsonOptions, cancellationToken);
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

    [LoggerMessage(Level = LogLevel.Error, Message = "Azure Protected Material text analysis failed")]
    private static partial void LogTextAnalysisFailed(ILogger logger, Exception ex);

    [LoggerMessage(Level = LogLevel.Error, Message = "Azure Protected Material code analysis failed")]
    private static partial void LogCodeAnalysisFailed(ILogger logger, Exception ex);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Azure Protected Material rate limited, retry {Attempt}/{MaxRetries} after {RetryAfter}")]
    private static partial void LogRateLimited(ILogger logger, int attempt, int maxRetries, TimeSpan retryAfter);

    [LoggerMessage(Level = LogLevel.Error, Message = "Azure Protected Material rate limit retries exhausted after {MaxRetries} attempts - failing open")]
    private static partial void LogRetryExhausted(ILogger logger, int maxRetries);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Azure Protected Material {MaterialType} analysis skipped: input is shorter than the service minimum of {MinLength} characters")]
    private static partial void LogBelowMinimumLength(ILogger logger, ProtectedMaterialType materialType, int minLength);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Azure Protected Material {MaterialType} input exceeds the per-request limit, analyzing it in {WindowCount} requests")]
    private static partial void LogSplitAnalysis(ILogger logger, ProtectedMaterialType materialType, int windowCount);

    // wire DTOs

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
