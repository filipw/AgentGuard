using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using AgentGuard.Azure.Pii;
using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Builders;
using AgentGuard.Core.Guardrails;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using TasmanianDevil;
using TasmanianDevil.Azure;
using Xunit;

namespace AgentGuard.Azure.Tests;

/// <summary>
/// What the Azure-backed PII rule reports when Azure AI Language could not analyze the text, or
/// could analyze only part of it.
/// </summary>
public class AzurePiiFailureTests
{
    private const string TextWithNameAndEmail = "John Smith's email is john@example.com";

    private static GuardrailContext Context(string text) => new() { Text = text, Phase = GuardrailPhase.Input };

    private static IGuardrailRule Rule(HttpMessageHandler handler, bool failOpen = true, Action<Exception>? onError = null)
    {
        var azureOptions = new AzurePiiOptions
        {
            SupportedEntities = [PiiEntities.Person],
            Endpoint = "https://my-resource.cognitiveservices.azure.com",
            SubscriptionKey = "key",
            FailOpen = failOpen,
            OnError = onError,
        };

        return new GuardrailPolicyBuilder()
            .RedactPiiWithAzure(new AzurePiiClient(new HttpClient(handler), azureOptions), azureOptions)
            .Build()
            .Rules.Single();
    }

    private static string Words(int length)
    {
        var words = new[] { "the", "meeting", "notes", "cover", "budget", "planning", "for", "next", "quarter" };
        var builder = new StringBuilder(length + 16);
        for (var i = 0; builder.Length < length; i++)
            builder.Append(words[i % words.Length]).Append(' ');

        return builder.ToString(0, length);
    }

    [Fact]
    public async Task EvaluateAsync_ShouldReportAnErrorAndKeepLocalRedactions_WhenAzureCannotBeReached()
    {
        var rule = Rule(LambdaHttpHandler.Unreachable());

        var result = await rule.EvaluateAsync(Context(TextWithNameAndEmail));

        result.IsError.Should().BeTrue();
        result.IsBlocked.Should().BeFalse();
        result.ModifiedText.Should().Be("John Smith's email is <EMAIL_ADDRESS>");
        result.Metadata!["error"].Should().Be(true);
        result.Metadata["errorDetail"].Should().BeOfType<string>().Which.Should().Contain("No connection could be made");
    }

    [Fact]
    public async Task EvaluateAsync_ShouldReportAnError_WhenAzureCannotBeReachedAndNothingElseIsFound()
    {
        var rule = Rule(LambdaHttpHandler.Unreachable());

        var result = await rule.EvaluateAsync(Context("John Smith called"));

        result.IsError.Should().BeTrue();
        result.IsBlocked.Should().BeFalse();
        result.IsModified.Should().BeFalse();
    }

    [Theory]
    [InlineData(HttpStatusCode.Unauthorized)]
    [InlineData(HttpStatusCode.TooManyRequests)]
    [InlineData(HttpStatusCode.InternalServerError)]
    public async Task EvaluateAsync_ShouldReportAnError_WhenAzureAnswersWithAFailureStatus(HttpStatusCode status)
    {
        var rule = Rule(new LanguageHandler(_ => new HttpResponseMessage(status)));

        var result = await rule.EvaluateAsync(Context(TextWithNameAndEmail));

        result.IsError.Should().BeTrue();
        result.IsBlocked.Should().BeFalse();
        result.ModifiedText.Should().Be("John Smith's email is <EMAIL_ADDRESS>");
    }

    [Fact]
    public async Task EvaluateAsync_ShouldReportAnError_WhenAzureRejectsTheDocument()
    {
        var rule = Rule(new LanguageHandler(_ => LambdaHttpHandler.Json(
            """
            { "kind": "PiiEntityRecognitionResults", "results": { "documents": [], "errors": [
                { "id": "1", "error": { "code": "InvalidArgument", "message": "Invalid document in request." } }
            ] } }
            """)));

        var result = await rule.EvaluateAsync(Context(TextWithNameAndEmail));

        result.IsError.Should().BeTrue();
        result.Metadata!["errorDetail"].Should().BeOfType<string>().Which.Should().Contain("Invalid document in request.");
    }

    [Fact]
    public async Task EvaluateAsync_ShouldReportAnError_WhenAzureDoesNotAnswerInTime()
    {
        var azureOptions = new AzurePiiOptions
        {
            SupportedEntities = [PiiEntities.Person],
            Endpoint = "https://my-resource.cognitiveservices.azure.com",
            SubscriptionKey = "key",
            Timeout = TimeSpan.FromMilliseconds(50),
        };
        var rule = new GuardrailPolicyBuilder()
            .RedactPiiWithAzure(new AzurePiiClient(new HttpClient(LambdaHttpHandler.Hanging()), azureOptions), azureOptions)
            .Build()
            .Rules.Single();

        var result = await rule.EvaluateAsync(Context(TextWithNameAndEmail));

        result.IsError.Should().BeTrue();
        result.IsBlocked.Should().BeFalse();
        result.ModifiedText.Should().Be("John Smith's email is <EMAIL_ADDRESS>");
    }

    [Fact]
    public async Task EvaluateAsync_ShouldBlockWithAnError_WhenAzureFailsAndFailOpenIsOff()
    {
        var rule = Rule(LambdaHttpHandler.Unreachable(), failOpen: false);

        var result = await rule.EvaluateAsync(Context(TextWithNameAndEmail));

        result.IsError.Should().BeTrue();
        result.IsBlocked.Should().BeTrue();
        result.IsModified.Should().BeFalse();
        result.Metadata!["errorDetail"].Should().BeOfType<string>().Which.Should().Contain("No connection could be made");
    }

    [Fact]
    public async Task EvaluateAsync_ShouldNotReportAnError_WhenAzureAnswers()
    {
        var rule = Rule(new LanguageHandler());

        var result = await rule.EvaluateAsync(Context(TextWithNameAndEmail));

        result.IsError.Should().BeFalse();
        result.ModifiedText.Should().Be("<PERSON>'s email is <EMAIL_ADDRESS>");
    }

    [Fact]
    public async Task EvaluateAsync_ShouldStillCallTheConfiguredErrorCallback_WhenAzureFails()
    {
        var seen = new List<Exception>();
        var rule = Rule(LambdaHttpHandler.Unreachable(), onError: seen.Add);

        await rule.EvaluateAsync(Context(TextWithNameAndEmail));

        seen.Should().ContainSingle().Which.Should().BeOfType<HttpRequestException>();
    }

    [Fact]
    public async Task EvaluateAsync_ShouldPropagateCancellation_WhenTheCallerCancels()
    {
        using var caller = new CancellationTokenSource();
        var rule = Rule(LambdaHttpHandler.CancelsThenFails(caller));

        var act = async () => await rule.EvaluateAsync(Context(TextWithNameAndEmail), caller.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    // a long text of which Azure analyzed only some windows is not a fully checked text

    [Fact]
    public async Task EvaluateAsync_ShouldReportAnErrorAndKeepWhatWasFound_WhenOneWindowOfALongTextFails()
    {
        var text = "John Smith opened. " + Words(7_000) + " Then John Smith spoke. " + Words(7_000) + " John Smith closed.";
        var handler = new LanguageHandler(call => call == 1 ? new HttpResponseMessage(HttpStatusCode.TooManyRequests) : null);
        var rule = Rule(handler);

        var result = await rule.EvaluateAsync(Context(text));

        handler.Calls.Should().BeGreaterThan(2);
        result.IsError.Should().BeTrue();
        result.IsBlocked.Should().BeFalse();
        result.IsModified.Should().BeTrue();
        result.ModifiedText.Should().StartWith("<PERSON> opened. ").And.EndWith(" <PERSON> closed.");
        result.Metadata!["errorDetail"].Should().BeOfType<string>().Which.Should().Contain("429");
        result.Metadata["entityTypes"].Should().BeEquivalentTo(new[] { PiiEntities.Person });
    }

    [Fact]
    public async Task EvaluateAsync_ShouldBlockWithAnError_WhenOneWindowOfALongTextFailsAndFailOpenIsOff()
    {
        var text = "John Smith opened. " + Words(12_000);
        var rule = Rule(
            new LanguageHandler(call => call == 1 ? new HttpResponseMessage(HttpStatusCode.TooManyRequests) : null),
            failOpen: false);

        var result = await rule.EvaluateAsync(Context(text));

        result.IsError.Should().BeTrue();
        result.IsBlocked.Should().BeTrue();
        result.IsModified.Should().BeFalse();
    }

    [Fact]
    public async Task EvaluateAsync_ShouldNotReportAnError_WhenEveryWindowOfALongTextIsAnalyzed()
    {
        var text = "John Smith opened. " + Words(12_000);
        var rule = Rule(new LanguageHandler());

        var result = await rule.EvaluateAsync(Context(text));

        result.IsError.Should().BeFalse();
        result.ModifiedText.Should().StartWith("<PERSON> opened. ");
    }

    [Fact]
    public async Task RunAsync_ShouldPassTheRedactedTextAndRecordTheError_WhenAzureFailsOpen()
    {
        var azureOptions = new AzurePiiOptions
        {
            SupportedEntities = [PiiEntities.Person],
            Endpoint = "https://my-resource.cognitiveservices.azure.com",
            SubscriptionKey = "key",
        };
        var policy = new GuardrailPolicyBuilder()
            .RedactPiiWithAzure(new AzurePiiClient(new HttpClient(LambdaHttpHandler.Unreachable()), azureOptions), azureOptions)
            .Build();
        var pipeline = new GuardrailPipeline(policy, NullLogger<GuardrailPipeline>.Instance);

        var result = await pipeline.RunAsync(Context(TextWithNameAndEmail));

        result.IsBlocked.Should().BeFalse();
        result.FinalText.Should().Be("John Smith's email is <EMAIL_ADDRESS>");
        result.AllResults.Should().ContainSingle().Which.IsError.Should().BeTrue();
    }

    /// <summary>
    /// Emulates Azure AI Language's <c>PiiEntityRecognition</c> call, reporting every "John Smith" as a
    /// Person, unless <paramref name="failure"/> returns a response for the zero-based call index.
    /// </summary>
    private sealed class LanguageHandler(Func<int, HttpResponseMessage?>? failure = null) : HttpMessageHandler
    {
        private int _calls;

        public int Calls => Volatile.Read(ref _calls);

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var call = Interlocked.Increment(ref _calls) - 1;
            if (failure?.Invoke(call) is { } failed)
                return failed;

            var body = JsonNode.Parse(await request.Content!.ReadAsStringAsync(cancellationToken))!;
            var text = body["analysisInput"]!["documents"]![0]!["text"]!.GetValue<string>();

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

            var response = new JsonObject
            {
                ["kind"] = "PiiEntityRecognitionResults",
                ["results"] = new JsonObject
                {
                    ["documents"] = new JsonArray(new JsonObject { ["id"] = "1", ["entities"] = entities }),
                    ["errors"] = new JsonArray(),
                },
            };

            return LambdaHttpHandler.Json(response.ToJsonString());
        }
    }
}
