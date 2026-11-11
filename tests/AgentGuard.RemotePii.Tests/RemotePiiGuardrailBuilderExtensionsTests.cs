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

    // a detector that cannot be reached must not look like text without names in it

    private static IGuardrailRule RemoteRule(IPiiDetectionClient client, bool failOpen = true, Action<Exception>? onError = null) =>
        new GuardrailPolicyBuilder()
            .RedactPiiWithRemote(client, new RemotePiiOptions
            {
                SupportedEntities = [PiiEntities.Person],
                FailOpen = failOpen,
                OnError = onError,
            })
            .Build()
            .Rules.Single();

    [Fact]
    public async Task EvaluateAsync_ShouldReportAnErrorAndKeepLocalRedactions_WhenTheRemoteDetectorFailsOpen()
    {
        var rule = RemoteRule(new StubPiiDetectionClient(throwing: new InvalidOperationException("remote is down")));

        var result = await rule.EvaluateAsync(Context("John Smith's email is john@example.com"));

        result.IsError.Should().BeTrue();
        result.IsBlocked.Should().BeFalse();
        result.IsModified.Should().BeTrue();
        result.ModifiedText.Should().Be("John Smith's email is <EMAIL_ADDRESS>");
        result.Metadata!["error"].Should().Be(true);
        result.Metadata["errorDetail"].Should().BeOfType<string>().Which.Should().Contain("remote is down");
        result.Metadata["entityTypes"].Should().BeAssignableTo<IEnumerable<string>>().Which.Should().Contain(PiiEntities.EmailAddress);
    }

    [Fact]
    public async Task EvaluateAsync_ShouldReportAnError_WhenTheRemoteDetectorFailsOpenAndNothingElseIsFound()
    {
        var rule = RemoteRule(new StubPiiDetectionClient(throwing: new HttpRequestException("401 (Unauthorized)")));

        var result = await rule.EvaluateAsync(Context("please call John Smith"));

        result.IsError.Should().BeTrue();
        result.IsBlocked.Should().BeFalse();
        result.IsModified.Should().BeFalse();
    }

    [Fact]
    public async Task EvaluateAsync_ShouldBlockWithAnError_WhenTheRemoteDetectorFailsAndFailOpenIsOff()
    {
        var rule = RemoteRule(new StubPiiDetectionClient(throwing: new InvalidOperationException("remote is down")), failOpen: false);

        var result = await rule.EvaluateAsync(Context("please call John Smith"));

        result.IsError.Should().BeTrue();
        result.IsBlocked.Should().BeTrue();
        result.Metadata!["errorDetail"].Should().BeOfType<string>().Which.Should().Contain("remote is down");
    }

    [Fact]
    public async Task EvaluateAsync_ShouldNotReportAnError_WhenTheRemoteDetectorAnswers()
    {
        var rule = RemoteRule(new StubPiiDetectionClient([]));

        var result = await rule.EvaluateAsync(Context("email john@example.com"));

        result.IsError.Should().BeFalse();
        result.IsModified.Should().BeTrue();
    }

    [Fact]
    public async Task EvaluateAsync_ShouldStillCallTheConfiguredErrorCallback_WhenTheRemoteDetectorFailsOpen()
    {
        var seen = new List<Exception>();
        var failure = new InvalidOperationException("remote is down");
        var rule = RemoteRule(new StubPiiDetectionClient(throwing: failure), onError: seen.Add);

        var result = await rule.EvaluateAsync(Context("please call John Smith"));

        result.IsError.Should().BeTrue();
        seen.Should().ContainSingle().Which.Should().BeSameAs(failure);
    }

    [Theory]
    [InlineData(HttpStatusCode.Unauthorized)]
    [InlineData(HttpStatusCode.NotFound)]
    [InlineData(HttpStatusCode.InternalServerError)]
    public async Task EvaluateAsync_ShouldReportAnError_WhenTheEndpointAnswersWithAFailureStatus(HttpStatusCode status)
    {
        using var httpClient = new HttpClient(new FakeHandler("""{"error": "nope"}""", status));
        var rule = new GuardrailPolicyBuilder()
            .RedactPiiWithRemote(httpClient, new RemotePiiOptions
            {
                SupportedEntities = [PiiEntities.Person],
                Endpoint = "https://detector.example.com/detect",
            })
            .Build()
            .Rules.Single();

        var result = await rule.EvaluateAsync(Context("please call John Smith"));

        result.IsError.Should().BeTrue();
        result.IsBlocked.Should().BeFalse();
    }

    [Fact]
    public async Task EvaluateAsync_ShouldReportAnError_WhenTheRemoteDetectorTimesOut()
    {
        var rule = new GuardrailPolicyBuilder()
            .RedactPiiWithRemote(new HangingPiiDetectionClient(), new RemotePiiOptions
            {
                SupportedEntities = [PiiEntities.Person],
                Timeout = TimeSpan.FromMilliseconds(100),
            })
            .Build()
            .Rules.Single();

        var result = await rule.EvaluateAsync(Context("please call John Smith"));

        result.IsError.Should().BeTrue();
        result.IsBlocked.Should().BeFalse();
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task EvaluateAsync_ShouldPropagateCancellation_WhenTheCallerCancels(bool failOpen)
    {
        var rule = RemoteRule(new HangingPiiDetectionClient(), failOpen);
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(50));

        var act = async () => await rule.EvaluateAsync(Context("please call John Smith"), cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    [Fact]
    public async Task EvaluateAsync_ShouldKeepAFailureToTheEvaluationItHappenedIn_WhenEvaluationsRunConcurrently()
    {
        var rule = RemoteRule(new FailingOnMarkerDetectionClient("UNREACHABLE"));

        var evaluations = Enumerable.Range(0, 40)
            .Select(i => rule.EvaluateAsync(Context(i % 2 == 0 ? $"note {i} UNREACHABLE" : $"note {i} is fine")).AsTask())
            .ToArray();
        var results = await Task.WhenAll(evaluations);

        for (var i = 0; i < results.Length; i++)
            results[i].IsError.Should().Be(i % 2 == 0, "evaluation {0} {1}", i, i % 2 == 0 ? "failed" : "succeeded");
    }

    [Fact]
    public async Task ShouldSurfaceTheFailureThroughThePipeline_WhenTheRemoteDetectorFailsOpen()
    {
        var policy = new GuardrailPolicyBuilder()
            .RedactPiiWithRemote(
                new StubPiiDetectionClient(throwing: new InvalidOperationException("remote is down")),
                new RemotePiiOptions { SupportedEntities = [PiiEntities.Person] })
            .Build();
        var pipeline = new GuardrailPipeline(policy, Microsoft.Extensions.Logging.Abstractions.NullLogger<GuardrailPipeline>.Instance);

        var result = await pipeline.RunAsync(Context("John Smith's email is john@example.com"));

        result.IsBlocked.Should().BeFalse();
        result.FinalText.Should().Be("John Smith's email is <EMAIL_ADDRESS>");
        result.AllResults.Should().ContainSingle().Which.IsError.Should().BeTrue();
    }

    // an entity name nothing recognizes would turn the remote detection into a no-op

    [Theory]
    [InlineData("EMAIL_ADRESS")]
    [InlineData("PERSN")]
    [InlineData("")]
    public void ShouldThrow_WhenASupportedEntityIsNotAKnownEntityType(string entity)
    {
        var act = () => new GuardrailPolicyBuilder()
            .RedactPiiWithRemote(new StubPiiDetectionClient([]), new RemotePiiOptions { SupportedEntities = [PiiEntities.Person, entity] });

        act.Should().Throw<ArgumentException>().WithMessage($"*'{entity}'*{PiiEntities.EmailAddress}*{PiiEntities.Person}*");
    }

    [Fact]
    public void ShouldThrow_WhenNoSupportedEntitiesAreGiven()
    {
        var act = () => new GuardrailPolicyBuilder()
            .RedactPiiWithRemote(new StubPiiDetectionClient([]), new RemotePiiOptions { SupportedEntities = [] });

        act.Should().Throw<ArgumentException>().WithMessage("*SupportedEntities*");
    }

    [Theory]
    [InlineData("person")]
    [InlineData("Person")]
    [InlineData(" PERSON ")]
    public async Task EvaluateAsync_ShouldDetectTheEntity_WhenItsNameIsSpelledInAnotherCase(string entity)
    {
        const string text = "please call John Smith";
        var client = new StubPiiDetectionClient([new RemotePiiEntity(PiiEntities.Person, 12, 22, 0.95)]);
        var rule = new GuardrailPolicyBuilder()
            .RedactPiiWithRemote(client, new RemotePiiOptions { SupportedEntities = [entity] })
            .Build()
            .Rules.Single();

        var result = await rule.EvaluateAsync(Context(text));

        result.ModifiedText.Should().Be("please call <PERSON>");
        client.LastEntities.Should().Equal(PiiEntities.Person);
    }

    [Fact]
    public async Task EvaluateAsync_ShouldAcceptTheDetectorsOwnNameForAnEntity_WhenTheCategoryMapHasIt()
    {
        const string text = "please call John Smith";
        var client = new StubPiiDetectionClient([new RemotePiiEntity("PER", 12, 22, 0.95)]);
        var rule = new GuardrailPolicyBuilder()
            .RedactPiiWithRemote(client, new RemotePiiOptions
            {
                SupportedEntities = ["per"],
                CategoryMap = new Dictionary<string, string> { ["PER"] = PiiEntities.Person },
            })
            .Build()
            .Rules.Single();

        var result = await rule.EvaluateAsync(Context(text));

        result.ModifiedText.Should().Be("please call <PERSON>");
    }

    [Fact]
    public async Task EvaluateAsync_ShouldDetectAnEntityTypeOfTheDetectorsOwn_WhenTheCategoryMapNamesIt()
    {
        const string text = "diagnosed with asthma";
        var client = new StubPiiDetectionClient([new RemotePiiEntity("condition", 15, 21, 0.9)]);
        var rule = new GuardrailPolicyBuilder()
            .RedactPiiWithRemote(client, new RemotePiiOptions
            {
                SupportedEntities = ["MEDICAL_CONDITION"],
                CategoryMap = new Dictionary<string, string> { ["condition"] = "MEDICAL_CONDITION" },
            })
            .Build()
            .Rules.Single();

        var result = await rule.EvaluateAsync(Context(text));

        result.ModifiedText.Should().Be("diagnosed with <MEDICAL_CONDITION>");
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

        public IReadOnlyList<string>? LastEntities { get; private set; }

        public ValueTask<IReadOnlyList<RemotePiiEntity>> DetectAsync(
            string text, string language, IReadOnlyList<string> entitiesRequested, CancellationToken ct = default)
        {
            LastLanguage = language;
            LastEntities = entitiesRequested;

            if (throwing is not null)
            {
                throw throwing;
            }

            return new ValueTask<IReadOnlyList<RemotePiiEntity>>(entities ?? []);
        }
    }

    private sealed class FakeHandler(string responseJson, HttpStatusCode status = HttpStatusCode.OK) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(status)
            {
                Content = new StringContent(responseJson, Encoding.UTF8, "application/json"),
            });
    }

    /// <summary>A detector that never answers, the way a service that stops responding behaves.</summary>
    private sealed class HangingPiiDetectionClient : IPiiDetectionClient
    {
        public async ValueTask<IReadOnlyList<RemotePiiEntity>> DetectAsync(
            string text, string language, IReadOnlyList<string> entities, CancellationToken ct = default)
        {
            await Task.Delay(Timeout.Infinite, ct);
            return [];
        }
    }

    /// <summary>A detector that fails, after yielding, for any text that contains the marker.</summary>
    private sealed class FailingOnMarkerDetectionClient(string marker) : IPiiDetectionClient
    {
        public async ValueTask<IReadOnlyList<RemotePiiEntity>> DetectAsync(
            string text, string language, IReadOnlyList<string> entities, CancellationToken ct = default)
        {
            await Task.Delay(5, ct);

            if (text.Contains(marker, StringComparison.Ordinal))
                throw new HttpRequestException("No connection could be made.");

            return [];
        }
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
