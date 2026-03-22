using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace AgentGuard.RemoteClassifier;

/// <summary>
/// Response format for HuggingFace text-classification endpoints.
/// Matches the output of <c>transformers.pipeline("text-classification")</c>.
/// </summary>
internal sealed class HuggingFaceClassificationResponse
{
    [JsonPropertyName("label")]
    public string Label { get; set; } = "";

    [JsonPropertyName("score")]
    public float Score { get; set; }
}

/// <summary>
/// Options for configuring the HTTP classifier.
/// </summary>
public sealed class HttpClassifierOptions
{
    /// <summary>
    /// Base URL of the classifier endpoint. Required.
    /// Examples:
    /// - "http://localhost:8000/classify" (custom FastAPI)
    /// - "http://localhost:11434/api/embeddings" (Ollama embedding mode)
    /// - "https://api-inference.huggingface.co/models/rogue-security/..." (HuggingFace Inference API)
    /// </summary>
    public required string EndpointUrl { get; init; }

    /// <summary>
    /// Optional API key for authenticated endpoints. Sent as "Bearer" in the Authorization header.
    /// </summary>
    public string? ApiKey { get; init; }

    /// <summary>
    /// The model name to include in the classification result metadata. Default: null.
    /// </summary>
    public string? ModelName { get; init; }

    /// <summary>
    /// The request format to use. Default: HuggingFace (text-classification pipeline format).
    /// </summary>
    public HttpClassifierRequestFormat RequestFormat { get; init; } = HttpClassifierRequestFormat.HuggingFace;
}

/// <summary>
/// Supported request/response formats for remote classifier endpoints.
/// </summary>
public enum HttpClassifierRequestFormat
{
    /// <summary>
    /// HuggingFace text-classification pipeline format.
    /// Request: { "inputs": "text" }
    /// Response: [{ "label": "jailbreak", "score": 0.99 }] or { "label": "...", "score": ... }
    /// </summary>
    HuggingFace,

    /// <summary>
    /// Simple JSON format with "text" input and "label"/"score" output.
    /// Request: { "text": "text" }
    /// Response: { "label": "jailbreak", "score": 0.99 }
    /// </summary>
    Simple
}

/// <summary>
/// HTTP-based remote classifier that calls a text-classification endpoint.
/// Supports HuggingFace Inference API format (default) and a simple custom format.
/// Works with any server that implements the text-classification API:
/// - Custom FastAPI/Flask wrapping <c>transformers.pipeline</c>
/// - HuggingFace Inference API
/// - HuggingFace TGI
/// - Any custom endpoint matching the supported formats
/// </summary>
public sealed class HttpClassifier : IRemoteClassifier, IDisposable
{
    private readonly HttpClient _httpClient;
    private readonly HttpClassifierOptions _options;
    private readonly bool _ownsClient;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };

    /// <summary>
    /// Creates a new HTTP classifier with a new HttpClient.
    /// </summary>
    public HttpClassifier(HttpClassifierOptions options) : this(new HttpClient(), options, ownsClient: true)
    {
    }

    /// <summary>
    /// Creates a new HTTP classifier with an existing HttpClient (for use with IHttpClientFactory).
    /// </summary>
    public HttpClassifier(HttpClient httpClient, HttpClassifierOptions options) : this(httpClient, options, ownsClient: false)
    {
    }

    private HttpClassifier(HttpClient httpClient, HttpClassifierOptions options, bool ownsClient)
    {
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _ownsClient = ownsClient;

        if (string.IsNullOrWhiteSpace(options.EndpointUrl))
            throw new ArgumentException("EndpointUrl is required.", nameof(options));

        if (options.ApiKey is not null)
        {
            _httpClient.DefaultRequestHeaders.Authorization =
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", options.ApiKey);
        }
    }

    /// <inheritdoc />
    public async Task<ClassificationResult> ClassifyAsync(string text, CancellationToken cancellationToken = default)
    {
        object requestBody = _options.RequestFormat switch
        {
            HttpClassifierRequestFormat.HuggingFace => new { inputs = text },
            HttpClassifierRequestFormat.Simple => new { text },
            _ => new { inputs = text }
        };

        var response = await _httpClient.PostAsJsonAsync(
            _options.EndpointUrl,
            requestBody,
            cancellationToken);

        response.EnsureSuccessStatusCode();

        var contentString = await response.Content.ReadAsStringAsync(cancellationToken);

        return ParseResponse(contentString);
    }

    private ClassificationResult ParseResponse(string json)
    {
        // HuggingFace returns an array: [{"label": "...", "score": ...}]
        // or sometimes a single object: {"label": "...", "score": ...}
        // Some endpoints return nested: [[{"label": "...", "score": ...}]]

        var trimmed = json.Trim();

        HuggingFaceClassificationResponse? parsed = null;

        if (trimmed.StartsWith("[[", StringComparison.Ordinal))
        {
            // Nested array: [[{...}]]
            var nested = JsonSerializer.Deserialize<HuggingFaceClassificationResponse[][]>(trimmed, JsonOptions);
            if (nested is { Length: > 0 } && nested[0] is { Length: > 0 })
                parsed = nested[0][0];
        }
        else if (trimmed.StartsWith('['))
        {
            // Array: [{...}]
            var array = JsonSerializer.Deserialize<HuggingFaceClassificationResponse[]>(trimmed, JsonOptions);
            if (array is { Length: > 0 })
                parsed = array[0];
        }
        else
        {
            // Single object: {...}
            parsed = JsonSerializer.Deserialize<HuggingFaceClassificationResponse>(trimmed, JsonOptions);
        }

        if (parsed is null)
        {
            throw new InvalidOperationException($"Failed to parse classifier response: {json}");
        }

        return new ClassificationResult
        {
            Label = parsed.Label,
            Score = parsed.Score,
            Model = _options.ModelName
        };
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_ownsClient)
            _httpClient.Dispose();
    }
}
