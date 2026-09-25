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

    /// <summary>
    /// Per-document attack detection results, one per input document in input order. A document that
    /// was split across several requests is flagged when any of its parts is.
    /// </summary>
    public IReadOnlyList<bool> DocumentAttacksDetected { get; init; } = [];

    /// <summary>
    /// True when an API call failed (error, timeout, retry exhaustion) and none of the calls that did
    /// complete detected an attack. The result is a fail-open default, not an actual classification.
    /// An attack that was detected is reported as such even when a later call failed, because the
    /// missing analysis could not have cleared it.
    /// </summary>
    public bool IsError { get; init; }
}

/// <summary>
/// Lightweight HTTP client for the Azure Content Safety Prompt Shield API
/// (<c>/contentsafety/text:shieldPrompt</c>).
/// Detects user prompt attacks (jailbreaks) and document attacks (indirect injection).
/// Input over the service's per-request limits is analyzed in several requests rather than rejected.
/// Fails open on errors.
/// </summary>
public sealed partial class AzurePromptShieldClient : IDisposable
{
    private const string ApiVersion = "2024-09-01";

    // the service's documented per-request limits: a prompt of up to 10K characters, and up to five
    // documents totalling 10K characters
    private const int MaxPromptLength = 10_000;
    private const int MaxDocumentsPerRequest = 5;
    private const int MaxDocumentsLength = 10_000;

    // windows of an oversized prompt or document overlap by this much, so an attack up to this long
    // that straddles a window boundary is still seen whole by one request
    private const int ChunkOverlap = 2_000;

    private readonly HttpClient _httpClient;
    private readonly bool _ownsHttpClient;
    private readonly string _endpoint;
    private readonly string _apiKey;

    private static readonly TimeSpan DefaultRetryDelay = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan MaxRetryDelay = TimeSpan.FromSeconds(10);
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

        // The endpoint and key are held per instance and applied per request rather than written
        // onto the HttpClient. Mutating a client that came from IHttpClientFactory is shared state:
        // BaseAddress ??= silently ignored the configured endpoint when one was already set, and
        // TryAddWithoutValidation appended a second subscription-key header for every additional
        // instance built over the same client.
        _endpoint = endpoint.TrimEnd('/');
        _apiKey = apiKey;
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
    /// <remarks>
    /// Input over the service's per-request limits (a 10K-character prompt; five documents totalling
    /// 10K characters) is split instead of being sent as one request the service would reject: the
    /// prompt into overlapping windows, each oversized document likewise, and the documents packed into
    /// batches that fit. Requests are sent one at a time, each prompt window paired with a document
    /// batch, and an attack found by any of them is reported. Whitespace-only prompts and documents are
    /// not sent. When a request fails the remaining ones are skipped, and the result is an error unless
    /// an attack was already detected.
    /// </remarks>
    public async ValueTask<PromptShieldResult> AnalyzeAsync(
        string userPrompt, IReadOnlyList<string>? documents = null,
        CancellationToken cancellationToken = default)
    {
        documents ??= [];

        var promptWindows = TextChunker.SplitToStrings(userPrompt, MaxPromptLength, ChunkOverlap).ToList();
        var documentBatches = BatchDocuments(documents);
        var requestCount = Math.Max(promptWindows.Count, documentBatches.Count);
        if (requestCount > 1)
            LogSplitAnalysis(_logger, requestCount);

        var userPromptAttackDetected = false;
        var documentAttacksDetected = new bool[documents.Count];
        var failed = false;

        for (var i = 0; i < requestCount; i++)
        {
            var batch = i < documentBatches.Count ? documentBatches[i] : [];
            var request = new ShieldPromptRequest
            {
                // a request carrying only a document batch leaves the prompt out; the service accepts
                // either field on its own
                UserPrompt = i < promptWindows.Count ? promptWindows[i] : null,
                Documents = batch.Select(part => part.Text).ToList()
            };

            try
            {
                var result = await ShieldAsync(request, cancellationToken);

                if (result?.UserPromptAnalysis?.AttackDetected == true)
                    userPromptAttackDetected = true;

                var analyses = result?.DocumentsAnalysis ?? [];
                for (var j = 0; j < batch.Count && j < analyses.Count; j++)
                {
                    if (analyses[j].AttackDetected)
                        documentAttacksDetected[batch[j].DocumentIndex] = true;
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                // the caller gave up; that is not an analysis failure and must not become a fail-open pass
                throw;
            }
            catch (Exception ex)
            {
                LogAnalysisFailed(_logger, ex);

                // stop rather than keep calling a failing service once per remaining request
                failed = true;
                break;
            }
        }

        // an attack found before the failure decides the verdict whatever the rest would have said
        if (failed && !userPromptAttackDetected && Array.IndexOf(documentAttacksDetected, true) < 0)
            return new PromptShieldResult { IsError = true }; // fail-open

        return new PromptShieldResult
        {
            UserPromptAttackDetected = userPromptAttackDetected,
            DocumentAttacksDetected = documentAttacksDetected
        };
    }

    /// <summary>Disposes the <see cref="HttpClient"/> when this instance created it.</summary>
    public void Dispose()
    {
        if (_ownsHttpClient)
            _httpClient.Dispose();
    }

    /// <summary>
    /// Packs the documents into request-sized batches of at most five parts and 10K characters,
    /// splitting any document over 10K characters into overlapping parts first. Each part keeps the
    /// index of the document it came from.
    /// </summary>
    private static List<List<DocumentPart>> BatchDocuments(IReadOnlyList<string> documents)
    {
        var batches = new List<List<DocumentPart>>();
        var batch = new List<DocumentPart>();
        var batchLength = 0;

        for (var index = 0; index < documents.Count; index++)
        {
            // a whitespace-only document yields no parts: it cannot carry an injection, and an empty
            // document risks the service rejecting the whole request
            foreach (var part in TextChunker.SplitToStrings(documents[index], MaxDocumentsLength, ChunkOverlap))
            {
                if (batch.Count == MaxDocumentsPerRequest || batchLength + part.Length > MaxDocumentsLength)
                {
                    batches.Add(batch);
                    batch = [];
                    batchLength = 0;
                }

                batch.Add(new DocumentPart(index, part));
                batchLength += part.Length;
            }
        }

        if (batch.Count > 0)
            batches.Add(batch);

        return batches;
    }

    private async Task<ShieldPromptResponse?> ShieldAsync(ShieldPromptRequest request, CancellationToken cancellationToken)
    {
        var url = $"/contentsafety/text:shieldPrompt?api-version={ApiVersion}";
        using var response = await SendWithRetryAsync(url, request, cancellationToken);
        response.EnsureSuccessStatusCode();

        return await response.Content.ReadFromJsonAsync<ShieldPromptResponse>(JsonOptions, cancellationToken);
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

    [LoggerMessage(Level = LogLevel.Error, Message = "Azure Prompt Shield analysis failed")]
    private static partial void LogAnalysisFailed(ILogger logger, Exception ex);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Azure Prompt Shield rate limited, retry {Attempt}/{MaxRetries} after {RetryAfter}")]
    private static partial void LogRateLimited(ILogger logger, int attempt, int maxRetries, TimeSpan retryAfter);

    [LoggerMessage(Level = LogLevel.Error, Message = "Azure Prompt Shield rate limit retries exhausted after {MaxRetries} attempts - failing open")]
    private static partial void LogRetryExhausted(ILogger logger, int maxRetries);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Azure Prompt Shield input exceeds the per-request limits, analyzing it in {RequestCount} requests")]
    private static partial void LogSplitAnalysis(ILogger logger, int requestCount);

    /// <summary>A request-sized piece of an input document, and the index of that document.</summary>
    private readonly record struct DocumentPart(int DocumentIndex, string Text);

    // wire DTOs

    private sealed class ShieldPromptRequest
    {
        public string? UserPrompt { get; init; }
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
