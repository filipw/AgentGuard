using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using AgentGuard.Azure.ProtectedMaterial;
using AgentGuard.Core.Abstractions;
using FluentAssertions;
using Xunit;

namespace AgentGuard.Azure.Tests;

public class AzureProtectedMaterialTests
{
    private const string Endpoint = "https://my-resource.cognitiveservices.azure.com";

    private static string Words(int length)
    {
        var words = new[] { "the", "model", "wrote", "an", "original", "answer", "about", "gardening" };
        var builder = new StringBuilder(length + 16);
        for (var i = 0; builder.Length < length; i++)
            builder.Append(words[i % words.Length]).Append(' ');

        return builder.ToString(0, length);
    }

    private static AzureProtectedMaterialClient CreateClient(FakeProtectedMaterialHandler handler) =>
        new(Endpoint, "key", new HttpClient(handler));

    private static GuardrailContext Context(string text) => new() { Text = text, Phase = GuardrailPhase.Output };

    [Fact]
    public async Task ShouldSkipTheCallAndPass_WhenTextIsShorterThanTheServiceMinimum()
    {
        // the service rejects text under 110 characters, so it is not sent
        var handler = new FakeProtectedMaterialHandler();
        var rule = new AzureProtectedMaterialRule(CreateClient(handler), new AzureProtectedMaterialOptions { OnError = ErrorBehavior.FailClosed });

        var result = await rule.EvaluateAsync(Context("Sure, here is a short answer."));

        result.IsBlocked.Should().BeFalse();
        result.IsError.Should().BeFalse();
        handler.Calls.Should().BeEmpty();
    }

    [Fact]
    public async Task ShouldSkipTheCall_WhenTextHasFewerCharactersThanItsLengthSuggests()
    {
        // 60 emoji are 120 UTF-16 code units, but only 60 characters - still under the minimum
        var handler = new FakeProtectedMaterialHandler();
        using var client = CreateClient(handler);

        var result = await client.AnalyzeTextAsync(string.Concat(Enumerable.Repeat("\U0001F3B5", 60)));

        result.IsError.Should().BeFalse();
        result.Detected.Should().BeFalse();
        handler.Calls.Should().BeEmpty();
    }

    [Fact]
    public async Task ShouldDetectProtectedText_WhenItComesAfterTheLimit()
    {
        // text over 10K characters is analyzed in windows
        var handler = new FakeProtectedMaterialHandler();
        var rule = new AzureProtectedMaterialRule(CreateClient(handler));

        var result = await rule.EvaluateAsync(Context(Words(12_000) + " " + FakeProtectedMaterialHandler.Lyrics));

        result.IsBlocked.Should().BeTrue();
        result.Metadata!["materialType"].Should().Be("text");
        handler.Calls.Should().HaveCountGreaterThan(1).And.OnlyContain(c => c.WithinLimits);
    }

    [Fact]
    public async Task ShouldStopAtTheFirstMatch_WhenTextSpansSeveralWindows()
    {
        var handler = new FakeProtectedMaterialHandler();
        using var client = CreateClient(handler);

        var result = await client.AnalyzeTextAsync(FakeProtectedMaterialHandler.Lyrics + " " + Words(30_000));

        result.Detected.Should().BeTrue();
        handler.Calls.Should().ContainSingle();
    }

    [Fact]
    public async Task ShouldAnalyzeEveryWindow_WhenLongTextIsClean()
    {
        var handler = new FakeProtectedMaterialHandler();
        using var client = CreateClient(handler);

        var result = await client.AnalyzeTextAsync(Words(25_000));

        result.Detected.Should().BeFalse();
        result.IsError.Should().BeFalse();
        handler.Calls.Should().HaveCount(3).And.OnlyContain(c => c.WithinLimits);
    }

    [Fact]
    public async Task ShouldDetectProtectedCodeAndCombineCitations_WhenCodeIsPastTheLimit()
    {
        var handler = new FakeProtectedMaterialHandler();
        var rule = new AzureProtectedMaterialRule(CreateClient(handler), new AzureProtectedMaterialOptions { AnalyzeCode = true });
        var line = "int value = compute(input);\n";
        var code = string.Concat(Enumerable.Repeat(line, 400)) + FakeProtectedMaterialHandler.Code + "\n" +
                   string.Concat(Enumerable.Repeat(line, 400)) + FakeProtectedMaterialHandler.Code + "\n";
        var context = Context("Here is the implementation you asked for, with an explanation of each step that follows below.");
        context.Properties["Code"] = code;

        var result = await rule.EvaluateAsync(context);

        result.IsBlocked.Should().BeTrue();
        result.Metadata!["materialType"].Should().Be("code");
        var citations = (IEnumerable<Dictionary<string, object>>)result.Metadata["codeCitations"];
        citations.Should().ContainSingle("the same citation from several windows is reported once");
        handler.Calls.Where(c => c.IsCode).Should().HaveCountGreaterThan(1).And.OnlyContain(c => c.WithinLimits);
    }

    [Theory]
    [InlineData(ErrorBehavior.FailOpen, false)]
    [InlineData(ErrorBehavior.FailClosed, true)]
    public async Task ShouldApplyOnError_WhenTheServiceFails(ErrorBehavior onError, bool expectBlocked)
    {
        var handler = new FakeProtectedMaterialHandler { FailFromCall = 0 };
        var rule = new AzureProtectedMaterialRule(CreateClient(handler), new AzureProtectedMaterialOptions { OnError = onError });

        var result = await rule.EvaluateAsync(Context(Words(500)));

        result.IsError.Should().BeTrue();
        result.IsBlocked.Should().Be(expectBlocked);
    }

    [Fact]
    public async Task ShouldReportAMatch_WhenCodeWasDetectedBeforeALaterWindowFailed()
    {
        var handler = new FakeProtectedMaterialHandler { FailFromCall = 1 };
        using var client = CreateClient(handler);

        var result = await client.AnalyzeCodeAsync(FakeProtectedMaterialHandler.Code + "\n" + Words(30_000));

        result.Detected.Should().BeTrue();
        result.IsError.Should().BeFalse();
        result.CodeCitations.Should().ContainSingle();
        handler.Calls.Should().HaveCount(2);
    }

    [Fact]
    public async Task ShouldPropagateCancellation_WhenTheCallerCancels()
    {
        // caller cancellation propagates rather than becoming an error result
        var rule = new AzureProtectedMaterialRule(CreateClient(new FakeProtectedMaterialHandler()));
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        var act = async () => await rule.EvaluateAsync(Context(Words(500)), cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    /// <summary>
    /// Emulates <c>text:detectProtectedMaterial</c> and <c>text:detectProtectedMaterialForCode</c>,
    /// including their documented limits: input over 10,000 or under 110 characters is rejected with a
    /// 400, as the service does.
    /// </summary>
    private sealed class FakeProtectedMaterialHandler : HttpMessageHandler
    {
        public const string Lyrics = "PROTECTED LYRICS that the service recognizes";
        public const string Code = "float Q_rsqrt_protected_marker(float number);";

        public List<MaterialCall> Calls { get; } = [];

        public int? FailFromCall { get; init; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var isCode = request.RequestUri!.AbsolutePath.EndsWith("ForCode", StringComparison.Ordinal);
            var body = JsonNode.Parse(await request.Content!.ReadAsStringAsync(cancellationToken))!.AsObject();
            var input = body[isCode ? "code" : "text"]!.GetValue<string>();
            var withinLimits = input.Length is >= 110 and <= 10_000;

            var index = Calls.Count;
            Calls.Add(new MaterialCall(isCode, input, withinLimits));

            if (FailFromCall is { } failFrom && index >= failFrom)
                return new HttpResponseMessage(HttpStatusCode.InternalServerError);

            if (!withinLimits)
            {
                return Json(HttpStatusCode.BadRequest, new JsonObject
                {
                    ["error"] = new JsonObject { ["code"] = "InvalidRequestBody", ["message"] = "The text length must be between 110 and 10000 characters." }
                });
            }

            var detected = input.Contains(isCode ? Code : Lyrics, StringComparison.Ordinal);
            var analysis = new JsonObject { ["detected"] = detected };
            if (isCode)
            {
                analysis["codeCitations"] = detected
                    ? new JsonArray(new JsonObject { ["license"] = "MIT", ["sourceUrls"] = new JsonArray("https://github.com/example/repo") })
                    : new JsonArray();
            }

            return Json(HttpStatusCode.OK, new JsonObject { ["protectedMaterialAnalysis"] = analysis });
        }

        private static HttpResponseMessage Json(HttpStatusCode status, JsonObject body) => new(status)
        {
            Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json")
        };
    }

    private sealed record MaterialCall(bool IsCode, string Input, bool WithinLimits);
}
