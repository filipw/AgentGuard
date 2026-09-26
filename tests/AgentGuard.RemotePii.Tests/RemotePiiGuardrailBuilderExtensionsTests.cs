using System.Net;
using System.Text;
using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Builders;
using AgentGuard.Core.Guardrails;
using AgentGuard.RemotePii;
using TasmanianDevil;
using TasmanianDevil.Remote;
using FluentAssertions;
using Xunit;

namespace AgentGuard.RemotePii.Tests;

public class RemotePiiGuardrailBuilderExtensionsTests
{
    private static GuardrailContext Context(string text) => new()
    {
        Text = text,
        Phase = GuardrailPhase.Input,
    };

    [Fact]
    public void ShouldAddPiiRule_ViaCustomClientOverload()
    {
        var client = new StubPiiDetectionClient([]);
        var policy = new GuardrailPolicyBuilder()
            .RedactPiiWithRemote(client, new RemotePiiOptions { SupportedEntities = [PiiEntities.Person] })
            .Build();

        policy.Rules.Should().ContainSingle().Which.Name.Should().Be("pii");
    }

    [Fact]
    public async Task EvaluateAsync_ShouldRedactRemoteAndLocalEntities_InOnePass()
    {
        const string text = "email John Smith at john@example.com";
        var personStart = text.IndexOf("John Smith", StringComparison.Ordinal);
        var client = new StubPiiDetectionClient(
            [new RemotePiiEntity(PiiEntities.Person, personStart, personStart + "John Smith".Length, 0.95)]);

        var policy = new GuardrailPolicyBuilder()
            .RedactPiiWithRemote(client, new RemotePiiOptions { SupportedEntities = [PiiEntities.Person] })
            .Build();
        var rule = policy.Rules.Single();

        var result = await rule.EvaluateAsync(Context(text));

        result.IsModified.Should().BeTrue();
        result.ModifiedText.Should().Contain("<PERSON>");
        result.ModifiedText.Should().Contain("<EMAIL_ADDRESS>");
    }

    [Fact]
    public async Task EvaluateAsync_ShouldStillRedactLocalEntities_WhenRemoteClientFailsOpen()
    {
        const string text = "email john@example.com";
        var client = new StubPiiDetectionClient(throwing: new InvalidOperationException("remote is down"));

        var policy = new GuardrailPolicyBuilder()
            .RedactPiiWithRemote(client, new RemotePiiOptions { SupportedEntities = [PiiEntities.Person] })
            .Build();
        var rule = policy.Rules.Single();

        var result = await rule.EvaluateAsync(Context(text));

        result.IsModified.Should().BeTrue();
        result.ModifiedText.Should().Contain("<EMAIL_ADDRESS>");
    }

    [Fact]
    public async Task EvaluateAsync_ShouldStillRunRemoteRecognizer_WhenPiiLanguageIsNonDefault()
    {
        // the remote recognizer is registered under the analysis language PiiRule uses
        // (piiOptions.Language), since the registry filters recognizers by language, and is told that
        // same language
        const string text = "Klaus Müller rief an";
        var nameStart = text.IndexOf("Klaus Müller", StringComparison.Ordinal);
        var client = new StubPiiDetectionClient(
            [new RemotePiiEntity(PiiEntities.Person, nameStart, nameStart + "Klaus Müller".Length, 0.95)]);

        var policy = new GuardrailPolicyBuilder()
            .RedactPiiWithRemote(
                client,
                new RemotePiiOptions { SupportedEntities = [PiiEntities.Person] },
                new PiiOptions { Language = "de" })
            .Build();
        var rule = policy.Rules.Single();

        var result = await rule.EvaluateAsync(Context(text));

        result.ModifiedText.Should().Contain("<PERSON>");
        client.LastLanguage.Should().Be("de");
    }

    [Fact]
    public async Task EvaluateAsync_ShouldRoundTripOverRealHttpTransport_ViaHttpClientOverload()
    {
        const string text = "our address is 221B Baker Street";
        var addressStart = text.IndexOf("221B Baker Street", StringComparison.Ordinal);
        var responseJson = $$"""
            { "entities": [ { "type": "ADDRESS", "start": {{addressStart}}, "end": {{addressStart + "221B Baker Street".Length}}, "score": 0.9 } ] }
            """;
        using var httpClient = new HttpClient(new FakeHandler(responseJson));

        var policy = new GuardrailPolicyBuilder()
            .RedactPiiWithRemote(httpClient, new RemotePiiOptions
            {
                SupportedEntities = [PiiEntities.Address],
                Endpoint = "https://detector.example.com/detect",
            })
            .Build();
        var rule = policy.Rules.Single();

        var result = await rule.EvaluateAsync(Context(text));

        result.ModifiedText.Should().Contain("<ADDRESS>");
    }

    [Fact]
    public void ShouldAddPiiRule_ViaEndpointShorthandOverload()
    {
        var policy = new GuardrailPolicyBuilder()
            .RedactPiiWithRemote("https://detector.example.com/detect", [PiiEntities.Person])
            .Build();

        policy.Rules.Should().ContainSingle().Which.Name.Should().Be("pii");
    }

    [Fact]
    public void ShouldThrow_WhenClientIsNull()
    {
        var act = () => new GuardrailPolicyBuilder()
            .RedactPiiWithRemote((IPiiDetectionClient)null!, new RemotePiiOptions { SupportedEntities = [PiiEntities.Person] });

        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void ShouldThrow_WhenRemoteOptionsIsNull()
    {
        var act = () => new GuardrailPolicyBuilder().RedactPiiWithRemote(remoteOptions: null!);

        act.Should().Throw<ArgumentNullException>();
    }

    private sealed class StubPiiDetectionClient(IReadOnlyList<RemotePiiEntity>? entities = null, Exception? throwing = null) : IPiiDetectionClient
    {
        public string? LastLanguage { get; private set; }

        public ValueTask<IReadOnlyList<RemotePiiEntity>> DetectAsync(
            string text, string language, IReadOnlyList<string> entitiesRequested, CancellationToken ct = default)
        {
            LastLanguage = language;

            if (throwing is not null)
            {
                throw throwing;
            }

            return new ValueTask<IReadOnlyList<RemotePiiEntity>>(entities ?? []);
        }
    }

    private sealed class FakeHandler(string responseJson) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(responseJson, Encoding.UTF8, "application/json"),
            });
    }

    // the recognizer wraps the detection client, which owns an HttpClient; disposing the rule
    // releases both

    [Fact]
    public void ShouldDisposeTheDetectionClient_WhenThePolicyIsDisposed()
    {
        var client = new TrackingDetectionClient();
        var policy = (GuardrailPolicy)new GuardrailPolicyBuilder("p")
            .RedactPiiWithRemote(client, new RemotePiiOptions
            {
                Endpoint = "https://detector.example.com/detect",
                SupportedEntities = [PiiEntities.Person],
            })
            .Build();

        client.Disposed.Should().BeFalse();

        policy.Dispose();

        client.Disposed.Should().BeTrue();
    }

    private sealed class TrackingDetectionClient : IPiiDetectionClient, IDisposable
    {
        public bool Disposed { get; private set; }

        public void Dispose() => Disposed = true;

        public ValueTask<IReadOnlyList<RemotePiiEntity>> DetectAsync(
            string text, string language, IReadOnlyList<string> entities, CancellationToken cancellationToken = default)
            => ValueTask.FromResult<IReadOnlyList<RemotePiiEntity>>([]);
    }
}
