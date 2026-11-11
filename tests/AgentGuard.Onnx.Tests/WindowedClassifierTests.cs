using AgentGuard.Core.Abstractions;
using FluentAssertions;
using Xunit;

namespace AgentGuard.Onnx.Tests;

/// <summary>
/// Unit tests for <see cref="WindowedClassifier{TScore}"/>, the evaluation the ONNX classifier rules
/// share, over a fake classifier (one token per word; a window containing <c>INJECT</c> scores 0.9).
/// </summary>
public class WindowedClassifierTests
{
    private const string RuleName = "stub-classifier";

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("  \t\n ")]
    public void ShouldPassWithoutClassifying_WhenTextIsEmptyOrWhitespace(string? text)
    {
        using var classifier = Create(WindowingTestHelpers.NotCalled<float>);

        var result = classifier.Evaluate(text, CancellationToken.None, out _);

        result.Should().NotBeNull();
        result!.IsBlocked.Should().BeFalse();
        result.IsError.Should().BeFalse();
    }

    [Fact]
    public void ShouldPass_WhenNoWindowBlocks()
    {
        using var classifier = Create(Score);

        var result = classifier.Evaluate(WindowingTestHelpers.Words(40), CancellationToken.None, out _);

        result.Should().NotBeNull();
        result!.IsBlocked.Should().BeFalse();
        result.IsError.Should().BeFalse();
    }

    [Fact]
    public void ShouldHandTheBlockingVerdictToTheRule_WhenAWindowBlocks()
    {
        using var classifier = Create(Score);
        var text = WindowingTestHelpers.WordsWithMarker(40, 30, "INJECT");

        var result = classifier.Evaluate(text, CancellationToken.None, out var blocked);

        result.Should().BeNull("the rule builds the block result itself");
        blocked.IsBlocked.Should().BeTrue();
        blocked.Score.Should().Be(0.9f);
        blocked.IsWindowed.Should().BeTrue();
        text.Substring(blocked.Window.Start, blocked.Window.Length).Should().Contain("INJECT");
    }

    [Fact]
    public void ShouldBlockAsTooLong_WhenInputNeedsMoreThanMaxWindows()
    {
        using var classifier = Create(Score, maxWindows: 2);

        var result = classifier.Evaluate(WindowingTestHelpers.Words(200), CancellationToken.None, out _);

        result.Should().NotBeNull();
        result!.IsBlocked.Should().BeTrue();
        result.IsError.Should().BeFalse("too long is a verdict, not a failure");
        result.Metadata.Should().ContainKey("inputTooLong");
    }

    [Fact]
    public void ShouldBlockWithAnErrorResult_WhenTheClassifierThrowsAndOnErrorIsFailClosed()
    {
        using var classifier = Create(_ => throw new FormatException("tokenizer went out of bounds"), ErrorBehavior.FailClosed);

        var result = classifier.Evaluate("some text", CancellationToken.None, out _);

        result.Should().NotBeNull();
        result!.IsBlocked.Should().BeTrue();
        result.IsError.Should().BeTrue();
        result.Severity.Should().Be(GuardrailSeverity.High);
        result.Reason.Should().Contain(RuleName);
        result.Metadata.Should().Contain("error", true);
        ((string)result.Metadata!["errorDetail"]).Should().Contain(nameof(FormatException)).And.Contain("tokenizer went out of bounds");
    }

    [Fact]
    public void ShouldPassQuietlyWithAnErrorResult_WhenTheClassifierThrowsAndOnErrorIsFailOpen()
    {
        using var classifier = Create(_ => throw new InvalidOperationException("boom"), ErrorBehavior.FailOpen);

        var result = classifier.Evaluate("some text", CancellationToken.None, out _);

        result.Should().NotBeNull();
        result!.IsBlocked.Should().BeFalse();
        result.IsError.Should().BeTrue();
        result.IsWarning.Should().BeFalse();
        result.Reason.Should().BeNull();
    }

    [Fact]
    public void ShouldPassWithAWarning_WhenTheClassifierThrowsAndOnErrorIsWarn()
    {
        using var classifier = Create(_ => throw new InvalidOperationException("boom"), ErrorBehavior.Warn);

        var result = classifier.Evaluate("some text", CancellationToken.None, out _);

        result.Should().NotBeNull();
        result!.IsBlocked.Should().BeFalse();
        result.IsError.Should().BeTrue();
        result.IsWarning.Should().BeTrue();
        result.Reason.Should().Contain(RuleName);
    }

    [Fact]
    public void ShouldReturnAnErrorResult_WhenTheTokenizerThrowsWhileCounting()
    {
        using var classifier = Create(
            WindowingTestHelpers.NotCalled<float>, countTokens: _ => throw new ArgumentException("invalid code points"));

        var result = classifier.Evaluate("some text", CancellationToken.None, out _);

        result.Should().NotBeNull();
        result!.IsBlocked.Should().BeTrue();
        result.IsError.Should().BeTrue();
        ((string)result.Metadata!["errorDetail"]).Should().Contain("invalid code points");
    }

    [Fact]
    public void ShouldReturnAnErrorResult_WhenALaterWindowFails()
    {
        var calls = 0;
        using var classifier = Create(_ => ++calls == 3 ? throw new InvalidOperationException("third window") : 0.1f);

        var result = classifier.Evaluate(WindowingTestHelpers.Words(100), CancellationToken.None, out _);

        result.Should().NotBeNull();
        result!.IsError.Should().BeTrue();
        result.IsBlocked.Should().BeTrue("the windows after the failure were never classified");
    }

    [Fact]
    public void ShouldThrowOperationCanceled_WhenCancelledBetweenWindows()
    {
        using var classifier = Create(Score, ErrorBehavior.FailOpen);
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var act = () => classifier.Evaluate(WindowingTestHelpers.Words(100), cts.Token, out _);

        act.Should().Throw<OperationCanceledException>();
    }

    [Fact]
    public void ShouldLetOperationCanceledThrough_WhenTheClassifierThrowsIt()
    {
        using var classifier = Create(_ => throw new OperationCanceledException(), ErrorBehavior.FailOpen);

        var act = () => classifier.Evaluate("some text", CancellationToken.None, out _);

        act.Should().Throw<OperationCanceledException>();
    }

    [Fact]
    public void ShouldLetObjectDisposedThrough_WhenTheClassifierThrowsIt()
    {
        using var classifier = Create(_ => throw new ObjectDisposedException("InferenceSession"), ErrorBehavior.FailOpen);

        var act = () => classifier.Evaluate("some text", CancellationToken.None, out _);

        act.Should().Throw<ObjectDisposedException>();
    }

    [Fact]
    public void ShouldThrowObjectDisposedNamingTheRule_WhenEvaluatedAfterDispose()
    {
        var classifier = Create(Score);
        classifier.Dispose();

        var act = () => classifier.Evaluate("some text", CancellationToken.None, out _);

        act.Should().Throw<ObjectDisposedException>().Which.ObjectName.Should().Be(typeof(StubRule).FullName);
    }

    [Fact]
    public void ShouldClassifyRepairedText_WhenInputHasUnpairedSurrogates()
    {
        var calls = new List<string>();
        using var classifier = Create(text =>
        {
            calls.Add(text);
            return 0.1f;
        });

        var result = classifier.Evaluate("abc\uD800def \uDC00", CancellationToken.None, out _);

        result!.IsError.Should().BeFalse();
        calls.Should().Equal("abc�def �");
    }

    [Fact]
    public void ShouldClassifyTheVeryInputString_WhenItNeedsNoPreparation()
    {
        var calls = new List<string>();
        using var classifier = Create(
            text =>
            {
                calls.Add(text);
                return 0.1f;
            },
            wordBreaker: TenCharacterWords());
        const string text = "short words only";

        classifier.Evaluate(text, CancellationToken.None, out _);

        calls.Should().ContainSingle().Which.Should().BeSameAs(text);
    }

    [Fact]
    public void ShouldClassifyLongWordsInPieces_WhenTheTokenizerHasAPerWordLimit()
    {
        var calls = new List<string>();
        using var classifier = Create(
            text =>
            {
                calls.Add(text);
                return 0.1f;
            },
            wordBreaker: TenCharacterWords());

        classifier.Evaluate("see aaaaaaaaaaaaaaaaaaaaaaaaa here", CancellationToken.None, out _);

        calls.Should().Equal("see aaaaaaaaaa aaaaaaaaaa aaaaa here");
    }

    [Fact]
    public void ShouldReportTheWindowInInputPositions_WhenLongWordsWereBroken()
    {
        using var classifier = Create(Score, wordBreaker: TenCharacterWords());
        var text = new string('a', 95) + " " + WindowingTestHelpers.WordsWithMarker(40, 30, "INJECT") + " " + new string('b', 95);

        var result = classifier.Evaluate(text, CancellationToken.None, out var blocked);

        result.Should().BeNull();
        var window = text.Substring(blocked.Window.Start, blocked.Window.Length);
        window.Should().Contain("INJECT");
        window.Should().NotStartWith(" ").And.NotEndWith(" ");
        WindowingTestHelpers.CountWords(window).Should().BeLessThanOrEqualTo(8, "the window is the one that was classified, located in the input");
    }

    [Fact]
    public async Task ShouldKeepTheSessionUntilTheEvaluationInFlightFinishes_WhenDisposedDuringClassification()
    {
        var session = new CountingDisposable();
        using var classifying = new ManualResetEventSlim();
        using var resume = new ManualResetEventSlim();
        var classifier = Create(
            _ =>
            {
                classifying.Set();
                resume.Wait();
                return 0.1f;
            },
            session: session);

        var evaluation = Task.Run(() => classifier.Evaluate("some text", CancellationToken.None, out _));
        classifying.Wait();
        classifier.Dispose();
        var releasedWhileClassifying = session.DisposeCount;
        resume.Set();
        var result = await evaluation;

        releasedWhileClassifying.Should().Be(0, "the classifier was still using the session");
        result!.IsBlocked.Should().BeFalse("the evaluation in flight finishes normally");
        session.DisposeCount.Should().Be(1, "the session is released once the evaluation has left");
    }

    [Fact]
    public async Task ShouldReleaseTheSession_WhenTheEvaluationInFlightFailsAfterDispose()
    {
        var session = new CountingDisposable();
        using var classifying = new ManualResetEventSlim();
        using var resume = new ManualResetEventSlim();
        var classifier = Create(
            _ =>
            {
                classifying.Set();
                resume.Wait();
                throw new OperationCanceledException();
            },
            session: session);

        var evaluation = Task.Run(() => classifier.Evaluate("some text", CancellationToken.None, out _));
        classifying.Wait();
        classifier.Dispose();
        resume.Set();
        var act = async () => await evaluation;

        await act.Should().ThrowAsync<OperationCanceledException>();
        session.DisposeCount.Should().Be(1);
    }

    private static float Score(string text) => text.Contains("INJECT") ? 0.9f : 0.1f;

    private static WindowedClassifier<float> Create(
        Func<string, float> classify,
        ErrorBehavior onError = ErrorBehavior.FailClosed,
        TokenCounter? countTokens = null,
        IDisposable? session = null,
        LongWordBreaker? wordBreaker = null,
        int maxWindows = 0) =>
        new(
            new StubRule(),
            "Stub",
            "StubOptions",
            session,
            classify,
            score => score >= 0.5f,
            score => score,
            new TextWindowSplitter(countTokens ?? WindowingTestHelpers.CountWords, windowSize: 8, windowOverlap: 2),
            maxWindows,
            onError,
            wordBreaker);

    // stands in for a tokenizer that cannot encode words of more than ten characters
    private static LongWordBreaker TenCharacterWords() =>
        new(
            text =>
            {
                var length = 0;
                foreach (var c in text)
                {
                    length = c == ' ' ? 0 : length + 1;
                    if (length > 10)
                        return false;
                }

                return true;
            },
            probeLength: 10);

    private sealed class StubRule : IGuardrailRule
    {
        public string Name => RuleName;

        public GuardrailPhase Phase => GuardrailPhase.Input;

        public ValueTask<GuardrailResult> EvaluateAsync(GuardrailContext context, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();
    }
}
