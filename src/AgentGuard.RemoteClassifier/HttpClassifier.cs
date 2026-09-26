using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;

namespace AgentGuard.RemoteClassifier;

/// <summary>
/// Options for configuring the HTTP classifier.
/// </summary>
public sealed class HttpClassifierOptions
{
    /// <summary>
    /// Base URL of the classifier endpoint. Required.
    /// Examples:
    /// - "http://localhost:8000/classify" (custom FastAPI)
    /// - "https://api-inference.huggingface.co/models/rogue-security/..." (HuggingFace Inference API)
    /// </summary>
    public required string EndpointUrl { get; init; }

    /// <summary>
    /// Optional API key for authenticated endpoints. Sent as "Bearer" in the Authorization header of
    /// each request to <see cref="EndpointUrl"/>; it is never written onto the <see cref="HttpClient"/>,
    /// so classifiers sharing a client each send their own key.
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
/// Supported request formats for remote classifier endpoints. Both read the same response shapes:
/// a <c>{ "label": "jailbreak", "score": 0.99 }</c> object, a list of them, or a list of such lists
/// (one per input, as the HuggingFace Inference API returns).
/// </summary>
public enum HttpClassifierRequestFormat
{
    /// <summary>
    /// HuggingFace text-classification pipeline format.
    /// Request: { "inputs": "text" }
    /// Response: [{ "label": "jailbreak", "score": 0.99 }], [[{ "label": "...", "score": ... }, ...]] or { "label": "...", "score": ... }
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
/// <remarks>
/// The endpoint may return the top label only or every label with its score, in any order: the
/// predicted label is the one with the highest score, and every score is kept in
/// <see cref="ClassificationResult.Scores"/>. A response of any other shape, or one without a label
/// and a score between 0.0 and 1.0, is an error rather than a clean result.
/// </remarks>
public sealed class HttpClassifier : IRemoteClassifier, IDisposable
{
    // how much of an unrecognized response body goes into the exception message
    private const int MaxResponseExcerptLength = 200;

    private readonly HttpClient _httpClient;
    private readonly HttpClassifierOptions _options;
    private readonly bool _ownsClient;

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

        // the API key is applied per request in ClassifyAsync, never to the client's default headers:
        // a client from IHttpClientFactory or DI is shared, so the last classifier constructed over it
        // would send its key to every other classifier's endpoint (and mutating DefaultRequestHeaders
        // while requests are in flight is not thread-safe).
    }

    /// <inheritdoc />
    /// <exception cref="HttpRequestException">Thrown when the endpoint fails or returns a non-success status code.</exception>
    /// <exception cref="JsonException">Thrown when the response is not JSON.</exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when the response is JSON but not a text-classification result: a
    /// <c>{"label", "score"}</c> object, a list of them or a list of such lists, holding at least one
    /// non-empty label with a score between 0.0 and 1.0.
    /// </exception>
    public async Task<ClassificationResult> ClassifyAsync(string text, CancellationToken cancellationToken = default)
    {
        object requestBody = _options.RequestFormat switch
        {
            HttpClassifierRequestFormat.HuggingFace => new { inputs = text },
            HttpClassifierRequestFormat.Simple => new { text },
            _ => new { inputs = text }
        };

        using var request = new HttpRequestMessage(HttpMethod.Post, _options.EndpointUrl)
        {
            Content = JsonContent.Create(requestBody)
        };

        if (_options.ApiKey is not null)
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _options.ApiKey);

        using var response = await _httpClient.SendAsync(request, cancellationToken);

        response.EnsureSuccessStatusCode();

        var contentString = await response.Content.ReadAsStringAsync(cancellationToken);
        var scores = ParseScores(contentString);

        // the endpoint may list the labels in any order, so the prediction is the highest-scoring one
        var predicted = scores[0];
        foreach (var score in scores)
        {
            if (score.Score > predicted.Score)
                predicted = score;
        }

        return new ClassificationResult
        {
            Label = predicted.Label,
            Score = predicted.Score,
            Model = _options.ModelName,
            Scores = scores
        };
    }

    /// <summary>
    /// Reads the labels and scores of a text-classification response: a single
    /// <c>{"label": ..., "score": ...}</c> object, a list of them (the output of
    /// <c>transformers.pipeline("text-classification")</c>), or a list of such lists - one per input,
    /// as the HuggingFace Inference API returns, whose labels are all taken. Property names are matched
    /// ignoring case.
    /// </summary>
    /// <param name="json">The response body.</param>
    /// <returns>The labels and scores, in response order; never empty.</returns>
    /// <exception cref="JsonException">Thrown when <paramref name="json"/> is not JSON.</exception>
    /// <exception cref="InvalidOperationException">Thrown when the JSON has any other shape or holds no label.</exception>
    internal static List<LabelScore> ParseScores(string json)
    {
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        var scores = new List<LabelScore>();

        if (root.ValueKind == JsonValueKind.Object)
        {
            scores.Add(ReadLabelScore(root, json));
        }
        else if (root.ValueKind == JsonValueKind.Array)
        {
            // a list of lists when the first item is one, otherwise a flat list; no mixing
            var nested = root.GetArrayLength() > 0 && root[0].ValueKind == JsonValueKind.Array;
            foreach (var item in root.EnumerateArray())
            {
                if (!nested)
                {
                    scores.Add(ReadLabelScore(item, json));
                    continue;
                }

                if (item.ValueKind != JsonValueKind.Array)
                    throw Unrecognized(json);

                foreach (var inner in item.EnumerateArray())
                    scores.Add(ReadLabelScore(inner, json));
            }
        }

        if (scores.Count == 0)
            throw Unrecognized(json);

        return scores;
    }

    private static LabelScore ReadLabelScore(JsonElement element, string json)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            string? label = null;
            double? score = null;
            foreach (var property in element.EnumerateObject())
            {
                if (property.Value.ValueKind == JsonValueKind.String && property.Name.Equals("label", StringComparison.OrdinalIgnoreCase))
                    label ??= property.Value.GetString();
                else if (property.Value.ValueKind == JsonValueKind.Number && property.Name.Equals("score", StringComparison.OrdinalIgnoreCase)
                         && property.Value.TryGetDouble(out var value))
                    score ??= value;
            }

            if (!string.IsNullOrWhiteSpace(label) && score is >= 0d and <= 1d)
                return new LabelScore(label, (float)score.Value);
        }

        throw Unrecognized(json);
    }

    private static InvalidOperationException Unrecognized(string json)
    {
        var excerpt = json.Length <= MaxResponseExcerptLength ? json : json[..MaxResponseExcerptLength] + "...";
        return new InvalidOperationException(
            "The classifier response is not a text-classification result (a {\"label\", \"score\"} object, a list of them, " +
            $"or a list of such lists, with a non-empty label and a score between 0.0 and 1.0): {excerpt}");
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_ownsClient)
            _httpClient.Dispose();
    }
}
