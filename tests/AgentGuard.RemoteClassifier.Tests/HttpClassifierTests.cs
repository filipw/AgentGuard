using AgentGuard.RemoteClassifier;
using FluentAssertions;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Xunit;

namespace AgentGuard.RemoteClassifier.Tests;

public class HttpClassifierTests
{
    private static HttpClassifier CreateClassifier(string responseJson, HttpStatusCode statusCode = HttpStatusCode.OK)
    {
        var handler = new FakeHttpHandler(responseJson, statusCode);
        var httpClient = new HttpClient(handler);
        return new HttpClassifier(httpClient, new HttpClassifierOptions
        {
            EndpointUrl = "http://localhost:8000/classify",
            ModelName = "test-model"
        });
    }

    // === Response Parsing ===

    [Fact]
    public async Task ShouldParseArrayResponse()
    {
        var classifier = CreateClassifier("""[{"label": "jailbreak", "score": 0.95}]""");

        var result = await classifier.ClassifyAsync("test input");

        result.Label.Should().Be("jailbreak");
        result.Score.Should().BeApproximately(0.95f, 0.001f);
        result.Model.Should().Be("test-model");
    }

    [Fact]
    public async Task ShouldParseNestedArrayResponse()
    {
        var classifier = CreateClassifier("""[[{"label": "clean", "score": 0.99}]]""");

        var result = await classifier.ClassifyAsync("safe input");

        result.Label.Should().Be("clean");
        result.Score.Should().BeApproximately(0.99f, 0.001f);
    }

    [Fact]
    public async Task ShouldParseSingleObjectResponse()
    {
        var classifier = CreateClassifier("""{"label": "injection", "score": 0.87}""");

        var result = await classifier.ClassifyAsync("test");

        result.Label.Should().Be("injection");
        result.Score.Should().BeApproximately(0.87f, 0.001f);
    }

    [Fact]
    public async Task ShouldHandleWhitespaceInResponse()
    {
        var classifier = CreateClassifier("""  [{"label": "clean", "score": 0.5}]  """);

        var result = await classifier.ClassifyAsync("test");

        result.Label.Should().Be("clean");
    }

    // === Error Handling ===

    [Fact]
    public async Task ShouldThrow_WhenServerReturns500()
    {
        var classifier = CreateClassifier("Internal Server Error", HttpStatusCode.InternalServerError);

        var act = () => classifier.ClassifyAsync("test");

        await act.Should().ThrowAsync<HttpRequestException>();
    }

    [Fact]
    public async Task ShouldThrow_WhenResponseIsInvalidJson()
    {
        var classifier = CreateClassifier("not json at all");

        var act = () => classifier.ClassifyAsync("test");

        await act.Should().ThrowAsync<Exception>();
    }

    // === Options Validation ===

    [Fact]
    public void ShouldThrow_WhenEndpointUrlIsEmpty()
    {
        var act = () => new HttpClassifier(new HttpClassifierOptions { EndpointUrl = "" });

        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void ShouldThrow_WhenHttpClientIsNull()
    {
        var act = () => new HttpClassifier(null!, new HttpClassifierOptions { EndpointUrl = "http://localhost" });

        act.Should().Throw<ArgumentNullException>();
    }

    // === Request Format ===

    [Fact]
    public async Task ShouldSendCorrectRequestBody_HuggingFaceFormat()
    {
        var handler = new FakeHttpHandler("""[{"label": "clean", "score": 0.99}]""");
        var httpClient = new HttpClient(handler);
        var classifier = new HttpClassifier(httpClient, new HttpClassifierOptions
        {
            EndpointUrl = "http://localhost:8000/classify",
            RequestFormat = HttpClassifierRequestFormat.HuggingFace
        });

        await classifier.ClassifyAsync("test input");

        handler.LastRequestBody.Should().Contain("\"inputs\"");
        handler.LastRequestBody.Should().Contain("test input");
    }

    [Fact]
    public async Task ShouldSendCorrectRequestBody_SimpleFormat()
    {
        var handler = new FakeHttpHandler("""{"label": "clean", "score": 0.99}""");
        var httpClient = new HttpClient(handler);
        var classifier = new HttpClassifier(httpClient, new HttpClassifierOptions
        {
            EndpointUrl = "http://localhost:8000/classify",
            RequestFormat = HttpClassifierRequestFormat.Simple
        });

        await classifier.ClassifyAsync("test input");

        handler.LastRequestBody.Should().Contain("\"text\"");
        handler.LastRequestBody.Should().Contain("test input");
    }

    [Fact]
    public async Task ShouldSendAuthorizationHeader_WhenApiKeySet()
    {
        var handler = new FakeHttpHandler("""[{"label": "clean", "score": 0.99}]""");
        var httpClient = new HttpClient(handler);
        var classifier = new HttpClassifier(httpClient, new HttpClassifierOptions
        {
            EndpointUrl = "http://localhost:8000/classify",
            ApiKey = "test-key-123"
        });

        await classifier.ClassifyAsync("test");

        handler.LastRequestHeaders.Should().ContainKey("Authorization");
        handler.LastRequestHeaders!["Authorization"].Should().Contain("Bearer test-key-123");
    }

    [Fact]
    public async Task ShouldSendEachClassifiersOwnKey_WhenClassifiersShareAnHttpClient()
    {
        // the key is sent per request and never set on the shared client
        var handler = new FakeHttpHandler("""[{"label": "clean", "score": 0.99}]""");
        using var shared = new HttpClient(handler);
        var a = new HttpClassifier(shared, new HttpClassifierOptions { EndpointUrl = "https://a.example/classify", ApiKey = "key-A" });
        var b = new HttpClassifier(shared, new HttpClassifierOptions { EndpointUrl = "https://b.example/classify", ApiKey = "key-B" });

        await a.ClassifyAsync("hello");
        await b.ClassifyAsync("hello");

        handler.Requests.Should().HaveCount(2);
        handler.Requests[0].Uri.Host.Should().Be("a.example");
        handler.Requests[0].Authorization.Should().Be("Bearer key-A");
        handler.Requests[1].Uri.Host.Should().Be("b.example");
        handler.Requests[1].Authorization.Should().Be("Bearer key-B");
        shared.DefaultRequestHeaders.Authorization.Should().BeNull("the shared client must not be mutated");
    }

    [Fact]
    public async Task ShouldSendNoKey_WhenAKeylessClassifierSharesAClientWithAKeyedOne()
    {
        var handler = new FakeHttpHandler("""[{"label": "clean", "score": 0.99}]""");
        using var shared = new HttpClient(handler);
        _ = new HttpClassifier(shared, new HttpClassifierOptions { EndpointUrl = "https://a.example/classify", ApiKey = "key-A" });
        var keyless = new HttpClassifier(shared, new HttpClassifierOptions { EndpointUrl = "https://third-party.example/classify" });

        await keyless.ClassifyAsync("hello");

        handler.Requests.Should().ContainSingle().Which.Authorization.Should().BeNull();
    }

    [Fact]
    public async Task ShouldUseTheCallersDefaultAuthorization_WhenNoApiKeyIsSet()
    {
        var handler = new FakeHttpHandler("""[{"label": "clean", "score": 0.99}]""");
        using var httpClient = new HttpClient(handler);
        httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "configured-by-caller");
        var classifier = new HttpClassifier(httpClient, new HttpClassifierOptions { EndpointUrl = "https://a.example/classify" });

        await classifier.ClassifyAsync("hello");

        handler.Requests.Should().ContainSingle().Which.Authorization.Should().Be("Bearer configured-by-caller");
    }

    // === Disposal ===

    [Fact]
    public void ShouldNotDisposeExternalHttpClient()
    {
        var handler = new FakeHttpHandler("""[{"label": "clean", "score": 0.99}]""");
        var httpClient = new HttpClient(handler);
        var classifier = new HttpClassifier(httpClient, new HttpClassifierOptions
        {
            EndpointUrl = "http://localhost:8000/classify"
        });

        classifier.Dispose();

        // The external HttpClient should still be usable (not disposed)
        // If it were disposed, this would throw ObjectDisposedException
        httpClient.BaseAddress.Should().BeNull(); // Just verify we can access it
    }

    /// <summary>
    /// Fake HTTP handler for testing without real network calls.
    /// </summary>
    private sealed class FakeHttpHandler : HttpMessageHandler
    {
        private readonly string _responseBody;
        private readonly HttpStatusCode _statusCode;

        public string? LastRequestBody { get; private set; }
        public Dictionary<string, string>? LastRequestHeaders { get; private set; }
        public List<(Uri Uri, string? Authorization)> Requests { get; } = [];

        public FakeHttpHandler(string responseBody, HttpStatusCode statusCode = HttpStatusCode.OK)
        {
            _responseBody = responseBody;
            _statusCode = statusCode;
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.Content is not null)
            {
                LastRequestBody = await request.Content.ReadAsStringAsync(cancellationToken);
            }

            LastRequestHeaders = new Dictionary<string, string>();
            foreach (var header in request.Headers)
            {
                LastRequestHeaders[header.Key] = string.Join(", ", header.Value);
            }

            Requests.Add((request.RequestUri!, request.Headers.Authorization?.ToString()));

            return new HttpResponseMessage(_statusCode)
            {
                Content = new StringContent(_responseBody, Encoding.UTF8, "application/json")
            };
        }
    }
}
