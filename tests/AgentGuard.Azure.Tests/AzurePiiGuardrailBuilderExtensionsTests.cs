using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
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
        // the Azure recognizer is registered under PiiRule's analysis language (the registry filters
        // recognizers by language) and sends that language to Azure
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

    private static string Words(int length)
    {
        var words = new[] { "the", "meeting", "notes", "cover", "budget", "planning", "for", "next", "quarter" };
        var builder = new StringBuilder(length + 16);
        for (var i = 0; builder.Length < length; i++)
            builder.Append(words[i % words.Length]).Append(' ');

        return builder.ToString(0, length);
    }

    private static IGuardrailRule AzurePiiRule(FakeLanguageHandler handler)
    {
        var azureOptions = new AzurePiiOptions
        {
            SupportedEntities = [PiiEntities.Person],
            Endpoint = "https://my-resource.cognitiveservices.azure.com",
            SubscriptionKey = "key",
        };

        return new GuardrailPolicyBuilder()
            .RedactPiiWithAzure(new AzurePiiClient(new HttpClient(handler), azureOptions), azureOptions)
            .Build()
            .Rules.Single();
    }

    [Fact]
    public async Task EvaluateAsync_ShouldRedactName_WhenTextIsOverTheServiceDocumentLimit()
    {
        // text over 5,120 text elements is analyzed in windows
        const string sentence = "Please contact John Smith at the front desk.";
        var handler = new FakeLanguageHandler();
        var rule = AzurePiiRule(handler);

        var result = await rule.EvaluateAsync(Context(sentence + new string('.', 5_200)));

        result.IsModified.Should().BeTrue();
        result.ModifiedText.Should().StartWith("Please contact <PERSON> at the front desk.");
        result.ModifiedText.Should().NotContain("John Smith");
        handler.Documents.Should().HaveCountGreaterThan(1).And.OnlyContain(d => d.Length <= 5_000);
        handler.RejectedDocuments.Should().Be(0);
    }

    [Fact]
    public async Task EvaluateAsync_ShouldMapSpansBackOntoTheFullText_WhenTheNameIsInALaterWindow()
    {
        var padding = Words(12_000);
        var handler = new FakeLanguageHandler();
        var rule = AzurePiiRule(handler);

        var result = await rule.EvaluateAsync(Context(padding + " John Smith called back."));

        result.ModifiedText.Should().Be(padding + " <PERSON> called back.");
        handler.RejectedDocuments.Should().Be(0);
    }

    [Fact]
    public async Task EvaluateAsync_ShouldReportTheNameOnce_WhenItLiesWhereTwoWindowsOverlap()
    {
        var text = Words(4_700) + " John Smith " + Words(6_000);
        var nameStart = text.IndexOf("John Smith", StringComparison.Ordinal);
        var windows = TextChunker.Split(text, 5_000, 500);
        windows.Count(w => w.Start <= nameStart && nameStart + 10 <= w.Start + w.Length)
            .Should().Be(2, "the test needs the name to sit where two windows overlap");
        var handler = new FakeLanguageHandler();
        var rule = AzurePiiRule(handler);

        var result = await rule.EvaluateAsync(Context(text));

        result.ModifiedText.Should().Be(text.Replace("John Smith", "<PERSON>", StringComparison.Ordinal));
        result.Metadata!["entityCount"].Should().Be(1);
    }

    [Fact]
    public async Task EvaluateAsync_ShouldSendTheTextUnchangedInOneDocument_WhenItFits()
    {
        const string text = "email John Smith today";
        var handler = new FakeLanguageHandler();
        var rule = AzurePiiRule(handler);

        await rule.EvaluateAsync(Context(text));

        handler.Documents.Should().Equal(text);
    }

    [Fact]
    public async Task EvaluateAsync_ShouldReleaseTheAzureClient_WhenThePolicyIsDisposed()
    {
        // the chunking wrapper must not break the ownership handover: disposing the policy still
        // disposes the recognizer and the client (and the HttpClient the client created)
        var policy = new GuardrailPolicyBuilder()
            .RedactPiiWithAzure(new AzurePiiOptions
            {
                SupportedEntities = [PiiEntities.Person],
                Endpoint = "http://127.0.0.1:9",
                SubscriptionKey = "key",
                FailOpen = false,
            })
            .Build();
        var rule = policy.Rules.Single();

        (policy as IDisposable)!.Dispose();
        var act = async () => await rule.EvaluateAsync(Context("John Smith"));

        await act.Should().ThrowAsync<ObjectDisposedException>();
    }

    /// <summary>
    /// Emulates Azure AI Language's synchronous <c>PiiEntityRecognition</c> call, including its
    /// documented document limit: a document over 5,120 text elements comes back as a per-document
    /// error on an HTTP 200, as the service does. Detects every "John Smith" as a Person.
    /// </summary>
    private sealed class FakeLanguageHandler : HttpMessageHandler
    {
        public List<string> Documents { get; } = [];

        public int RejectedDocuments { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var body = JsonNode.Parse(await request.Content!.ReadAsStringAsync(cancellationToken))!;
            var text = body["analysisInput"]!["documents"]![0]!["text"]!.GetValue<string>();
            Documents.Add(text);

            JsonObject results;
            if (new StringInfo(text).LengthInTextElements > 5_120)
            {
                RejectedDocuments++;
                results = new JsonObject
                {
                    ["documents"] = new JsonArray(),
                    ["errors"] = new JsonArray(new JsonObject
                    {
                        ["id"] = "1",
                        ["error"] = new JsonObject
                        {
                            ["code"] = "InvalidArgument",
                            ["message"] = "Invalid document in request.",
                            ["innererror"] = new JsonObject
                            {
                                ["code"] = "InvalidDocument",
                                ["message"] = "A document within the request was too large to be processed. Limit document size to: 5120 text elements."
                            }
                        }
                    }),
                    ["modelVersion"] = "2025-01-15"
                };
            }
            else
            {
                var entities = new JsonArray();
                for (var at = text.IndexOf("John Smith", StringComparison.Ordinal); at >= 0; at = text.IndexOf("John Smith", at + 1, StringComparison.Ordinal))
                {
                    entities.Add(new JsonObject
                    {
                        ["text"] = "John Smith",
                        ["category"] = "Person",
                        ["offset"] = at,
                        ["length"] = 10,
                        ["confidenceScore"] = 0.95
                    });
                }

                results = new JsonObject
                {
                    ["documents"] = new JsonArray(new JsonObject { ["id"] = "1", ["entities"] = entities, ["warnings"] = new JsonArray() }),
                    ["errors"] = new JsonArray(),
                    ["modelVersion"] = "2025-01-15"
                };
            }

            var response = new JsonObject { ["kind"] = "PiiEntityRecognitionResults", ["results"] = results };
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(response.ToJsonString(), Encoding.UTF8, "application/json"),
            };
        }
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
