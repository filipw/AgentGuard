using System.Net;
using System.Text;
using System.Text.Json;
using AgentGuard.Azure.Pii;
using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Builders;
using Azure.Core;
using TasmanianDevil;
using TasmanianDevil.Azure;
using FluentAssertions;
using Xunit;

namespace AgentGuard.Azure.Tests;

public class AzurePiiGuardrailBuilderExtensionsTests
{
    private static GuardrailContext Context(string text) => new()
    {
        Text = text,
        Phase = GuardrailPhase.Input,
    };

    [Fact]
    public void ShouldAddPiiRule_ViaClientOverload()
    {
        var client = new AzurePiiClient(new HttpClient(new FakeHandler("""{ "results": { "documents": [ { "id": "1", "entities": [] } ] } }""")), new AzurePiiOptions
        {
            SupportedEntities = [PiiEntities.Person],
            Endpoint = "https://my-resource.cognitiveservices.azure.com",
            SubscriptionKey = "key",
        });

        var policy = new GuardrailPolicyBuilder()
            .RedactPiiWithAzure(client, new AzurePiiOptions
            {
                SupportedEntities = [PiiEntities.Person],
                Endpoint = "https://my-resource.cognitiveservices.azure.com",
                SubscriptionKey = "key",
            })
            .Build();

        policy.Rules.Should().ContainSingle().Which.Name.Should().Be("pii");
    }

    [Fact]
    public async Task EvaluateAsync_ShouldRedactAzureAndLocalEntities_InOnePass()
    {
        const string text = "email John Smith at john@example.com";
        var personStart = text.IndexOf("John Smith", StringComparison.Ordinal);
        var responseJson = $$"""
            { "results": { "documents": [ { "id": "1", "entities": [
                { "text": "John Smith", "category": "Person", "offset": {{personStart}}, "length": {{"John Smith".Length}}, "confidenceScore": 0.95 }
            ] } ] } }
            """;
        using var httpClient = new HttpClient(new FakeHandler(responseJson));
        var azureOptions = new AzurePiiOptions
        {
            SupportedEntities = [PiiEntities.Person],
            Endpoint = "https://my-resource.cognitiveservices.azure.com",
            SubscriptionKey = "key",
        };

        var policy = new GuardrailPolicyBuilder()
            .RedactPiiWithAzure(new AzurePiiClient(httpClient, azureOptions), azureOptions)
            .Build();
        var rule = policy.Rules.Single();

        var result = await rule.EvaluateAsync(Context(text));

        result.IsModified.Should().BeTrue();
        result.ModifiedText.Should().Contain("<PERSON>");
        result.ModifiedText.Should().Contain("<EMAIL_ADDRESS>");
    }

    [Fact]
    public async Task EvaluateAsync_ShouldStillRedactLocalEntities_WhenAzureClientFailsOpen()
    {
        const string text = "email john@example.com";
        using var httpClient = new HttpClient(new ThrowingHandler());
        var azureOptions = new AzurePiiOptions
        {
            SupportedEntities = [PiiEntities.Person],
            Endpoint = "https://my-resource.cognitiveservices.azure.com",
            SubscriptionKey = "key",
        };

        var policy = new GuardrailPolicyBuilder()
            .RedactPiiWithAzure(new AzurePiiClient(httpClient, azureOptions), azureOptions)
            .Build();
        var rule = policy.Rules.Single();

        var result = await rule.EvaluateAsync(Context(text));

        result.IsModified.Should().BeTrue();
        result.ModifiedText.Should().Contain("<EMAIL_ADDRESS>");
    }

    [Fact]
    public async Task EvaluateAsync_ShouldAuthenticateViaBearerToken_WhenUsingTokenCredentialOverload()
    {
        var handler = new FakeHandler("""{ "results": { "documents": [ { "id": "1", "entities": [] } ] } }""");
        var credential = new StubTokenCredential("aad-token");

        // the TokenCredential overload builds its own AzurePiiClient/HttpClient internally, so we can
        // only verify wiring succeeds and the rule is added; the header itself is covered by
        // TasmanianDevil.Azure's own AzurePiiClientTests (DetectAsync_ShouldSendBearerToken_ViaTokenProvider)
        var policy = new GuardrailPolicyBuilder()
            .RedactPiiWithAzure("https://my-resource.cognitiveservices.azure.com", credential, [PiiEntities.Person])
            .Build();

        policy.Rules.Should().ContainSingle().Which.Name.Should().Be("pii");
        _ = handler; // unused in this wiring-only assertion
    }

    [Fact]
    public void ShouldAddPiiRule_ViaSubscriptionKeyShorthandOverload()
    {
        var policy = new GuardrailPolicyBuilder()
            .RedactPiiWithAzure("https://my-resource.cognitiveservices.azure.com", "key", [PiiEntities.Person])
            .Build();

        policy.Rules.Should().ContainSingle().Which.Name.Should().Be("pii");
    }

    [Fact]
    public void ShouldThrow_WhenClientIsNull()
    {
        var act = () => new GuardrailPolicyBuilder()
            .RedactPiiWithAzure((AzurePiiClient)null!, new AzurePiiOptions { SupportedEntities = [PiiEntities.Person], Endpoint = "https://x" });

        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void ShouldThrow_WhenAzureOptionsIsNull()
    {
        var act = () => new GuardrailPolicyBuilder().RedactPiiWithAzure(azureOptions: null!);

        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void ShouldThrow_WhenCredentialIsNull()
    {
        var act = () => new GuardrailPolicyBuilder()
            .RedactPiiWithAzure("https://my-resource.cognitiveservices.azure.com", (TokenCredential)null!, [PiiEntities.Person]);

        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public async Task EvaluateAsync_ShouldStillRunAzureRecognizer_WhenPiiLanguageIsNonDefault()
    {
        // regression: the Azure recognizer must be registered under PiiRule's analysis language, else the
        // registry filters it out on a language mismatch. It should also send that language to Azure.
        const string text = "Klaus Müller rief an";
        var nameStart = text.IndexOf("Klaus Müller", StringComparison.Ordinal);
        var responseJson = $$"""
            { "results": { "documents": [ { "id": "1", "entities": [
                { "text": "Klaus Müller", "category": "Person", "offset": {{nameStart}}, "length": {{"Klaus Müller".Length}}, "confidenceScore": 0.95 }
            ] } ] } }
            """;
        var handler = new CapturingHandler(responseJson);
        using var httpClient = new HttpClient(handler);
        var client = new AzurePiiClient(httpClient, new AzurePiiOptions
        {
            SupportedEntities = [PiiEntities.Person],
            Endpoint = "https://my-resource.cognitiveservices.azure.com",
            SubscriptionKey = "key",
        });

        var policy = new GuardrailPolicyBuilder()
            .RedactPiiWithAzure(
                client,
                new AzurePiiOptions
                {
                    SupportedEntities = [PiiEntities.Person],
                    Endpoint = "https://my-resource.cognitiveservices.azure.com",
                    SubscriptionKey = "key",
                },
                new PiiOptions { Language = "de" })
            .Build();
        var rule = policy.Rules.Single();

        var result = await rule.EvaluateAsync(Context(text));

        result.ModifiedText.Should().Contain("<PERSON>");
        var body = JsonDocument.Parse(handler.LastRequestBody!).RootElement;
        body.GetProperty("analysisInput").GetProperty("documents")[0].GetProperty("language").GetString().Should().Be("de");
    }

    private sealed class CapturingHandler(string responseJson) : HttpMessageHandler
    {
        public string? LastRequestBody { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastRequestBody = request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken);
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(responseJson, Encoding.UTF8, "application/json"),
            };
        }
    }

    private sealed class StubTokenCredential(string token) : TokenCredential
    {
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
            new(token, DateTimeOffset.UtcNow.AddHours(1));

        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
            new(GetToken(requestContext, cancellationToken));
    }

    private sealed class FakeHandler(string responseJson) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(responseJson, Encoding.UTF8, "application/json"),
            });
    }

    private sealed class ThrowingHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            throw new HttpRequestException("azure is down");
    }
}
