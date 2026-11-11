using AgentGuard.Core.Abstractions;
using FluentAssertions;
using TasmanianDevil;
using TasmanianDevil.Analyzer;
using TasmanianDevil.Analyzer.Context;
using Xunit;

namespace AgentGuard.Pii.Tests;

/// <summary>
/// What <see cref="PiiRule"/> returns when one of its recognizers could not analyze the text.
/// </summary>
public class PiiRuleRecognizerFailureTests
{
    private const string TextWithEmail = "write to john@example.com";

    private static GuardrailContext Context(string text) => new()
    {
        Text = text,
        Phase = GuardrailPhase.Input,
    };

    private static PiiRule RuleWith(EntityRecognizer recognizer, ErrorBehavior onError = ErrorBehavior.FailOpen)
    {
        var registry = PiiRecognizers.CreateRegistry("en", null);
        registry.AddRecognizer(recognizer);
        var engine = new AnalyzerEngine(registry, new LemmaContextAwareEnhancer(), defaultScoreThreshold: 0);

        return new PiiRule(analyzer: engine, ruleOptions: new PiiRuleOptions { OnError = onError });
    }

    [Fact]
    public async Task ShouldReportAnErrorAndKeepTheRedactions_WhenARecognizerReportsAFailure()
    {
        var rule = RuleWith(new FailureReportingRecognizer(new TimeoutException("too slow")));

        var result = await rule.EvaluateAsync(Context(TextWithEmail));

        result.IsError.Should().BeTrue();
        result.IsBlocked.Should().BeFalse();
        result.IsWarning.Should().BeFalse();
        result.IsModified.Should().BeTrue();
        result.ModifiedText.Should().Be("write to <EMAIL_ADDRESS>");
        result.RuleName.Should().Be("pii");
        result.Metadata!["error"].Should().Be(true);
        result.Metadata["errorDetail"].Should().Be("Test detector failed: TimeoutException: too slow");
        result.Metadata["entityCount"].Should().BeOfType<int>().Which.Should().BePositive();
    }

    [Fact]
    public async Task ShouldReportAnError_WhenARecognizerReportsAFailureAndNothingIsFound()
    {
        var rule = RuleWith(new FailureReportingRecognizer(new TimeoutException("too slow")));

        var result = await rule.EvaluateAsync(Context("nothing to see here"));

        result.IsError.Should().BeTrue();
        result.IsBlocked.Should().BeFalse();
        result.IsModified.Should().BeFalse();
        result.Metadata!["errorDetail"].Should().Be("Test detector failed: TimeoutException: too slow");
    }

    [Fact]
    public async Task ShouldWarnAndKeepTheRedactions_WhenARecognizerReportsAFailureAndOnErrorIsWarn()
    {
        var rule = RuleWith(new FailureReportingRecognizer(new TimeoutException("too slow")), ErrorBehavior.Warn);

        var result = await rule.EvaluateAsync(Context(TextWithEmail));

        result.IsError.Should().BeTrue();
        result.IsWarning.Should().BeTrue();
        result.IsBlocked.Should().BeFalse();
        result.ModifiedText.Should().Be("write to <EMAIL_ADDRESS>");
        result.Reason.Should().Contain("EMAIL_ADDRESS").And.Contain("incomplete");
    }

    [Fact]
    public async Task ShouldBlock_WhenARecognizerReportsAFailureAndOnErrorIsFailClosed()
    {
        var rule = RuleWith(new FailureReportingRecognizer(new TimeoutException("too slow")), ErrorBehavior.FailClosed);

        var result = await rule.EvaluateAsync(Context(TextWithEmail));

        result.IsError.Should().BeTrue();
        result.IsBlocked.Should().BeTrue();
        result.IsModified.Should().BeFalse();
        result.RuleName.Should().Be("pii");
        result.Metadata!["errorDetail"].Should().Be("Test detector failed: TimeoutException: too slow");
    }

    [Fact]
    public async Task ShouldBlock_WhenARecognizerThrowsAndOnErrorIsFailClosed()
    {
        var rule = RuleWith(new ThrowingRecognizer(new InvalidOperationException("detector crashed")), ErrorBehavior.FailClosed);

        var result = await rule.EvaluateAsync(Context(TextWithEmail));

        result.IsError.Should().BeTrue();
        result.IsBlocked.Should().BeTrue();
        result.Metadata!["errorDetail"].Should().BeOfType<string>().Which.Should().Contain("detector crashed");
    }

    [Theory]
    [InlineData(ErrorBehavior.FailOpen)]
    [InlineData(ErrorBehavior.Warn)]
    public async Task ShouldLetTheExceptionThrough_WhenARecognizerThrowsAndOnErrorDoesNotBlock(ErrorBehavior onError)
    {
        // there is no partial result to pass along, and passing the text unredacted would hide the failure
        var rule = RuleWith(new ThrowingRecognizer(new InvalidOperationException("detector crashed")), onError);

        var act = async () => await rule.EvaluateAsync(Context(TextWithEmail));

        await act.Should().ThrowAsync<InvalidOperationException>().WithMessage("detector crashed");
    }

    [Fact]
    public async Task ShouldSummarizeTheFailures_WhenSeveralAreReported()
    {
        var rule = RuleWith(new FailureReportingRecognizer(new TimeoutException("too slow"), reports: 4));

        var result = await rule.EvaluateAsync(Context(TextWithEmail));

        result.Metadata!["errorDetail"].Should().Be("Test detector failed: TimeoutException: too slow (4 failed calls)");
    }

    [Fact]
    public async Task ShouldNotCarryAFailureOver_ToTheNextEvaluation()
    {
        var recognizer = new FailureReportingRecognizer(new TimeoutException("too slow"));
        var rule = RuleWith(recognizer);
        await rule.EvaluateAsync(Context(TextWithEmail));
        recognizer.Failure = null;

        var result = await rule.EvaluateAsync(Context(TextWithEmail));

        result.IsError.Should().BeFalse();
        result.ModifiedText.Should().Be("write to <EMAIL_ADDRESS>");
    }

    [Fact]
    public async Task ShouldKeepFailuresApart_WhenEvaluationsRunConcurrently()
    {
        var rule = RuleWith(new FailsOnMarkerRecognizer("FAIL"));

        var results = await Task.WhenAll(Enumerable.Range(0, 40).Select(i =>
            Task.Run(async () => await rule.EvaluateAsync(Context(i % 2 == 0 ? "FAIL john@example.com" : "fine john@example.com")))));

        for (var i = 0; i < results.Length; i++)
            results[i].IsError.Should().Be(i % 2 == 0);
    }

    [Fact]
    public async Task ReportRecognizerFailure_ShouldDoNothing_OutsideAnEvaluation()
    {
        PiiRule.ReportRecognizerFailure("Test detector", new TimeoutException("too slow"));

        var result = await new PiiRule().EvaluateAsync(Context(TextWithEmail));

        result.IsError.Should().BeFalse();
    }

    [Fact]
    public async Task ShouldThrowOperationCanceled_WhenTheCallerCancelsWhileARecognizerSwallowsTheFailure()
    {
        using var caller = new CancellationTokenSource();
        var rule = RuleWith(new CancelingRecognizer(caller));

        var act = async () => await rule.EvaluateAsync(Context(TextWithEmail), caller.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    private abstract class TestRecognizer() : EntityRecognizer(["TEST_ENTITY"], name: "test", supportedLanguage: "en")
    {
    }

    /// <summary>Finds nothing and reports that it could not look, the way a fail-open remote detector does.</summary>
    private sealed class FailureReportingRecognizer(Exception? failure, int reports = 1) : TestRecognizer
    {
        public Exception? Failure { get; set; } = failure;

        public override IReadOnlyList<RecognizerResult> Analyze(string text, IReadOnlyList<string> entities)
        {
            for (var i = 0; i < reports && Failure is not null; i++)
                PiiRule.ReportRecognizerFailure("Test detector", Failure);

            return [];
        }
    }

    private sealed class FailsOnMarkerRecognizer(string marker) : TestRecognizer
    {
        public override bool RequiresAsync => true;

        public override IReadOnlyList<RecognizerResult> Analyze(string text, IReadOnlyList<string> entities) => [];

        public override async ValueTask<IReadOnlyList<RecognizerResult>> AnalyzeAsync(
            string text, IReadOnlyList<string> entities, CancellationToken ct = default)
        {
            await Task.Yield();
            if (text.Contains(marker, StringComparison.Ordinal))
                PiiRule.ReportRecognizerFailure("Test detector", new TimeoutException("too slow"));

            return [];
        }
    }

    private sealed class ThrowingRecognizer(Exception failure) : TestRecognizer
    {
        public override IReadOnlyList<RecognizerResult> Analyze(string text, IReadOnlyList<string> entities) => throw failure;
    }

    private sealed class CancelingRecognizer(CancellationTokenSource caller) : TestRecognizer
    {
        public override IReadOnlyList<RecognizerResult> Analyze(string text, IReadOnlyList<string> entities)
        {
            caller.Cancel();
            PiiRule.ReportRecognizerFailure("Test detector", new IOException("The connection was aborted."));
            return [];
        }
    }
}
