using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using AgentGuard.Azure.ContentSafety;
using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Rules.ContentSafety;
using Azure;
using Azure.AI.ContentSafety;
using Azure.Core.Pipeline;
using FluentAssertions;
using Xunit;

namespace AgentGuard.Azure.Tests;

public class AzureContentSafetyClassifierChunkingTests
{
    private static string Words(int length)
    {
        var words = new[] { "the", "weather", "today", "is", "mild", "and", "pleasant", "outside" };
        var builder = new StringBuilder(length + 16);
        for (var i = 0; builder.Length < length; i++)
            builder.Append(words[i % words.Length]).Append(' ');

        return builder.ToString(0, length);
    }

    private static AzureContentSafetyClassifier CreateClassifier(FakeContentSafetyHandler handler)
    {
        var options = new ContentSafetyClientOptions { Transport = new HttpClientTransport(handler) };
        options.Retry.MaxRetries = 0;

        var client = new ContentSafetyClient(new Uri("https://my-resource.cognitiveservices.azure.com"), new AzureKeyCredential("key"), options);
        return new AzureContentSafetyClassifier(client);
    }

    private static GuardrailContext Context(string text) => new() { Text = text, Phase = GuardrailPhase.Output };

    [Fact]
    public async Task ShouldBlockHatefulContent_WhenTextFitsInOneRequest()
    {
        var handler = new FakeContentSafetyHandler();
        var rule = new ContentSafetyRule(new ContentSafetyOptions(), CreateClassifier(handler));

        var result = await rule.EvaluateAsync(Context(FakeContentSafetyHandler.Hateful));

        result.IsBlocked.Should().BeTrue();
        handler.Texts.Should().ContainSingle();
    }

    [Fact]
    public async Task ShouldBlockHatefulContent_WhenTextIsPaddedPastTheLimit()
    {
        // text over 10K characters is analyzed in windows
        var handler = new FakeContentSafetyHandler();
        var rule = new ContentSafetyRule(new ContentSafetyOptions(), CreateClassifier(handler));

        var result = await rule.EvaluateAsync(Context(FakeContentSafetyHandler.Hateful + new string('.', 10_000)));

        result.IsBlocked.Should().BeTrue();
        result.IsError.Should().BeFalse();
        handler.Texts.Should().HaveCountGreaterThan(1).And.OnlyContain(t => t.Length <= 10_000);
    }

    [Theory]
    [InlineData("start")]
    [InlineData("straddling")]
    [InlineData("end")]
    public async Task ShouldBlockHatefulContent_WhereverItSitsInALongText(string position)
    {
        var hateful = FakeContentSafetyHandler.Hateful;
        var text = position switch
        {
            "start" => hateful + " " + Words(25_000),
            "end" => Words(25_000) + " " + hateful,
            _ => Words(10_000 - hateful.Length / 2) + hateful + " " + Words(15_000)
        };
        var handler = new FakeContentSafetyHandler();
        var rule = new ContentSafetyRule(new ContentSafetyOptions(), CreateClassifier(handler));

        var result = await rule.EvaluateAsync(Context(text));

        result.IsBlocked.Should().BeTrue();
        handler.Texts.Should().OnlyContain(t => t.Length <= 10_000);
    }

    [Fact]
    public async Task ShouldReportTheWorstSeverityPerCategory_WhenWindowsDisagree()
    {
        var handler = new FakeContentSafetyHandler();
        var classifier = CreateClassifier(handler);
        var text = FakeContentSafetyHandler.Violent + " " + Words(12_000) + " " + FakeContentSafetyHandler.GraphicallyViolent;

        var result = await classifier.AnalyzeWithOptionsAsync(text, new ContentSafetyOptions());

        result.IsError.Should().BeFalse();
        result.CategoriesAnalysis.Should().Equal(
            new ContentSafetyAnalysis { Category = ContentSafetyCategory.Hate, Severity = ContentSafetySeverity.Safe },
            new ContentSafetyAnalysis { Category = ContentSafetyCategory.SelfHarm, Severity = ContentSafetySeverity.Safe },
            new ContentSafetyAnalysis { Category = ContentSafetyCategory.Sexual, Severity = ContentSafetySeverity.Safe },
            new ContentSafetyAnalysis { Category = ContentSafetyCategory.Violence, Severity = ContentSafetySeverity.High });
    }

    [Fact]
    public async Task ShouldReportABlocklistMatchOnce_WhenOverlappingWindowsBothSeeIt()
    {
        var handler = new FakeContentSafetyHandler();
        var classifier = CreateClassifier(handler);

        // the blocked term sits where the first two windows overlap
        var text = Words(9_500) + " " + FakeContentSafetyHandler.BlockedTerm + " " + Words(12_000);

        var result = await classifier.AnalyzeWithOptionsAsync(text, new ContentSafetyOptions { BlocklistNames = ["banned"] });

        handler.Texts.Count(t => t.Contains(FakeContentSafetyHandler.BlockedTerm, StringComparison.Ordinal)).Should().Be(2);
        result.BlocklistMatches.Should().ContainSingle().Which.BlocklistItemText.Should().Be(FakeContentSafetyHandler.BlockedTerm);
    }

    [Fact]
    public async Task ShouldStopAfterABlocklistHit_WhenHaltOnBlocklistHitIsSet()
    {
        var handler = new FakeContentSafetyHandler();
        var classifier = CreateClassifier(handler);
        var text = FakeContentSafetyHandler.BlockedTerm + " " + Words(30_000);

        var result = await classifier.AnalyzeWithOptionsAsync(
            text, new ContentSafetyOptions { BlocklistNames = ["banned"], HaltOnBlocklistHit = true });

        result.BlocklistMatches.Should().ContainSingle();
        handler.Texts.Should().ContainSingle();
    }

    [Fact]
    public async Task ShouldNotSendWhitespaceOnlyWindows_WhenTextIsMostlyWhitespace()
    {
        var handler = new FakeContentSafetyHandler();
        var classifier = CreateClassifier(handler);

        var result = await classifier.AnalyzeWithOptionsAsync("hello" + new string(' ', 40_000), new ContentSafetyOptions());

        result.IsError.Should().BeFalse();
        handler.Texts.Should().ContainSingle().Which.Length.Should().BeLessThanOrEqualTo(10_000);
    }

    [Theory]
    [InlineData(ErrorBehavior.FailOpen, false)]
    [InlineData(ErrorBehavior.FailClosed, true)]
    public async Task ShouldApplyOnError_WhenTheServiceFails(ErrorBehavior onError, bool expectBlocked)
    {
        var handler = new FakeContentSafetyHandler { FailFromCall = 0 };
        var rule = new ContentSafetyRule(new ContentSafetyOptions { OnError = onError }, CreateClassifier(handler));

        var result = await rule.EvaluateAsync(Context(FakeContentSafetyHandler.Hateful));

        result.IsError.Should().BeTrue();
        result.IsBlocked.Should().Be(expectBlocked);
    }

    [Fact]
    public async Task ShouldStopAtTheFirstFailure_WhenMoreWindowsRemain()
    {
        var handler = new FakeContentSafetyHandler { FailFromCall = 1 };
        var classifier = CreateClassifier(handler);

        var result = await classifier.AnalyzeWithOptionsAsync(Words(30_000), new ContentSafetyOptions());

        result.IsError.Should().BeTrue();
        handler.Texts.Should().HaveCount(2, "the window after the failed one is never sent");
    }

    [Fact]
    public async Task ShouldBlock_WhenAViolationWasFoundBeforeALaterWindowFailed()
    {
        var handler = new FakeContentSafetyHandler { FailFromCall = 1 };
        var rule = new ContentSafetyRule(new ContentSafetyOptions(), CreateClassifier(handler));

        var result = await rule.EvaluateAsync(Context(FakeContentSafetyHandler.Hateful + " " + Words(30_000)));

        result.IsBlocked.Should().BeTrue();
        result.IsError.Should().BeFalse();
    }

    [Fact]
    public async Task ShouldReportAnError_WhenTheWindowsBeforeTheFailureStayedWithinTheAllowedSeverity()
    {
        // low severity is allowed by default, so it does not decide the verdict on its own
        var handler = new FakeContentSafetyHandler { FailFromCall = 1 };
        var rule = new ContentSafetyRule(new ContentSafetyOptions(), CreateClassifier(handler));

        var result = await rule.EvaluateAsync(Context(FakeContentSafetyHandler.Rude + " " + Words(30_000)));

        result.IsError.Should().BeTrue();
        result.IsBlocked.Should().BeFalse();
    }

    [Fact]
    public async Task ShouldPropagateCancellation_WhenTheCallerCancels()
    {
        var classifier = CreateClassifier(new FakeContentSafetyHandler());
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        var act = async () => await classifier.AnalyzeWithOptionsAsync(Words(30_000), new ContentSafetyOptions(), cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    /// <summary>
    /// Emulates <c>text:analyze</c>, including its documented limit: text over 10,000 characters is
    /// rejected with a 400, as the service does.
    /// </summary>
    private sealed class FakeContentSafetyHandler : HttpMessageHandler
    {
        public const string Hateful = "HATEFUL content";
        public const string Rude = "RUDE content";
        public const string Violent = "VIOLENT content";
        public const string GraphicallyViolent = "GRAPHICALLY VIOLENT content";
        public const string BlockedTerm = "forbidden-term";

        public List<string> Texts { get; } = [];

        public int? FailFromCall { get; init; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var body = JsonNode.Parse(await request.Content!.ReadAsStringAsync(cancellationToken))!.AsObject();
            var text = body["text"]!.GetValue<string>();
            var blocklists = body["blocklistNames"]?.AsArray().Select(b => b!.GetValue<string>()).ToList() ?? [];

            var index = Texts.Count;
            Texts.Add(text);

            if (FailFromCall is { } failFrom && index >= failFrom)
                return Json(HttpStatusCode.InternalServerError, Error("InternalServerError", "The service is unavailable."));

            if (text.Length > 10_000)
                return Json(HttpStatusCode.BadRequest, Error("InvalidRequestBody", "The text is longer than 10000 characters."));

            var hate = text.Contains(Hateful, StringComparison.Ordinal) ? 6 : text.Contains(Rude, StringComparison.Ordinal) ? 2 : 0;
            var violence = text.Contains(GraphicallyViolent, StringComparison.Ordinal) ? 6 : text.Contains(Violent, StringComparison.Ordinal) ? 4 : 0;

            var matches = new JsonArray();
            if (blocklists.Contains("banned") && text.Contains(BlockedTerm, StringComparison.Ordinal))
            {
                matches.Add(new JsonObject
                {
                    ["blocklistName"] = "banned",
                    ["blocklistItemId"] = "item-1",
                    ["blocklistItemText"] = BlockedTerm
                });
            }

            return Json(HttpStatusCode.OK, new JsonObject
            {
                ["blocklistsMatch"] = matches,
                ["categoriesAnalysis"] = new JsonArray(
                    Category("Hate", hate), Category("SelfHarm", 0), Category("Sexual", 0), Category("Violence", violence))
            });
        }

        private static JsonObject Category(string name, int severity) => new() { ["category"] = name, ["severity"] = severity };

        private static JsonObject Error(string code, string message) =>
            new() { ["error"] = new JsonObject { ["code"] = code, ["message"] = message } };

        private static HttpResponseMessage Json(HttpStatusCode status, JsonObject body) => new(status)
        {
            Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json")
        };
    }
}
