using AgentGuard.Core.Abstractions;
using Kyoto;
using FluentAssertions;
using Xunit;

namespace AgentGuard.Onnx.Tests;

/// <summary>
/// Unit tests for <see cref="OpirSafetyRule"/> that can be exercised without real model files
/// (properties, options validation, early-return behaviour).
/// </summary>
public class OpirSafetyRuleTests
{
    private static readonly string[] Labels = ["toxicity", "hate speech", "violence", "sexual content", "self-harm", "harassment"];

    private static OpirSafetyRule CreateRuleWithoutSession() =>
        new(WindowingTestHelpers.NotCalled<OpirScore>, Labels, WindowingTestHelpers.CountWords, prefixTokenCount: 30, new OpirSafetyOptions
        {
            ModelPath = "/nonexistent/model.onnx",
            TokenizerPath = "/nonexistent/spm.model",
            PrefixPath = "/nonexistent/prefix.json"
        });

    [Fact]
    public void ShouldHaveCorrectName()
    {
        var rule = CreateRuleWithoutSession();
        rule.Name.Should().Be("opir-content-safety");
    }

    [Fact]
    public void ShouldHaveCorrectPhase()
    {
        var rule = CreateRuleWithoutSession();
        rule.Phase.Should().Be(GuardrailPhase.Input);
    }

    [Fact]
    public void ShouldHaveCorrectOrder()
    {
        var rule = CreateRuleWithoutSession();
        rule.Order.Should().Be(50);
    }

    [Fact]
    public void ShouldDefaultThresholdToZeroPointFive()
    {
        var options = new OpirSafetyOptions
        {
            ModelPath = "/nonexistent/model.onnx",
            TokenizerPath = "/nonexistent/spm.model",
            PrefixPath = "/nonexistent/prefix.json"
        };
        options.Threshold.Should().Be(0.5f);
    }

    [Fact]
    public void ShouldThrow_WhenModelPathIsNull()
    {
#pragma warning disable CS9035 // required member must be set
        var act = () => new OpirSafetyRule(new OpirSafetyOptions
        {
            ModelPath = null!,
            TokenizerPath = "/nonexistent/spm.model",
            PrefixPath = "/nonexistent/prefix.json"
        });
#pragma warning restore CS9035

        act.Should().Throw<ArgumentException>().WithMessage("*ModelPath*");
    }

    [Fact]
    public void ShouldThrow_WhenModelPathDoesNotExist()
    {
        var act = () => new OpirSafetyRule(new OpirSafetyOptions
        {
            ModelPath = "/nonexistent/does-not-exist.onnx",
            TokenizerPath = "/nonexistent/spm.model",
            PrefixPath = "/nonexistent/prefix.json"
        });

        act.Should().Throw<FileNotFoundException>().WithMessage("*does-not-exist.onnx*");
    }

    [Fact]
    public void ShouldThrow_WhenTokenizerPathDoesNotExist()
    {
        var modelTemp = Path.GetTempFileName();
        try
        {
            var act = () => new OpirSafetyRule(new OpirSafetyOptions
            {
                ModelPath = modelTemp,
                TokenizerPath = "/nonexistent/spm.model",
                PrefixPath = "/nonexistent/prefix.json"
            });

            act.Should().Throw<FileNotFoundException>().WithMessage("*spm.model*");
        }
        finally
        {
            File.Delete(modelTemp);
        }
    }

    [Fact]
    public void ShouldThrow_WhenPrefixPathDoesNotExist()
    {
        var modelTemp = Path.GetTempFileName();
        var tokenizerTemp = Path.GetTempFileName();
        try
        {
            var act = () => new OpirSafetyRule(new OpirSafetyOptions
            {
                ModelPath = modelTemp,
                TokenizerPath = tokenizerTemp,
                PrefixPath = "/nonexistent/prefix.json"
            });

            act.Should().Throw<FileNotFoundException>().WithMessage("*prefix.json*");
        }
        finally
        {
            File.Delete(modelTemp);
            File.Delete(tokenizerTemp);
        }
    }

    [Fact]
    public void ShouldThrow_WhenThresholdIsAboveOne()
    {
        var modelTemp = Path.GetTempFileName();
        var tokenizerTemp = Path.GetTempFileName();
        var prefixTemp = Path.GetTempFileName();
        try
        {
            var act = () => new OpirSafetyRule(new OpirSafetyOptions
            {
                ModelPath = modelTemp,
                TokenizerPath = tokenizerTemp,
                PrefixPath = prefixTemp,
                Threshold = 1.1f
            });

            act.Should().Throw<ArgumentOutOfRangeException>().WithMessage("*Threshold*");
        }
        finally
        {
            File.Delete(modelTemp);
            File.Delete(tokenizerTemp);
            File.Delete(prefixTemp);
        }
    }

    [Theory]
    [InlineData(-0.1f)]
    [InlineData(float.NaN)]
    [InlineData(float.PositiveInfinity)]
    public void ShouldThrow_WhenThresholdIsNotANumberBetweenZeroAndOne(float threshold)
    {
        // checked before any model file is opened
        var act = () => new OpirSafetyRule(new OpirSafetyOptions
        {
            ModelPath = "/nonexistent/model.onnx",
            TokenizerPath = "/nonexistent/spm.model",
            PrefixPath = "/nonexistent/prefix.json",
            Threshold = threshold
        });

        act.Should().Throw<ArgumentOutOfRangeException>().WithMessage("*Threshold*");
    }

    [Theory]
    [InlineData(2)]
    [InlineData(0)]
    public void ShouldThrow_WhenMaxTokenLengthLeavesNoRoomForInput(int maxTokenLength)
    {
        var act = () => new OpirSafetyRule(new OpirSafetyOptions
        {
            ModelPath = "/nonexistent/model.onnx",
            TokenizerPath = "/nonexistent/spm.model",
            PrefixPath = "/nonexistent/prefix.json",
            MaxTokenLength = maxTokenLength
        });

        act.Should().Throw<ArgumentOutOfRangeException>().WithMessage("*MaxTokenLength*");
    }

    [Fact]
    public void ShouldThrow_WhenTheTestConstructorGetsANaNThreshold()
    {
        var act = () => new OpirSafetyRule(
            WindowingTestHelpers.NotCalled<OpirScore>,
            Labels,
            WindowingTestHelpers.CountWords,
            prefixTokenCount: 30,
            new OpirSafetyOptions { ModelPath = "m", TokenizerPath = "t", PrefixPath = "p", Threshold = float.NaN });

        act.Should().Throw<ArgumentOutOfRangeException>().WithMessage("*Threshold*");
    }

    [Fact]
    public async Task ShouldScanEveryWindow_WhenMaxWindowsIsZero()
    {
        // 0 means no limit
        var calls = new List<string>();
        var rule = new OpirSafetyRule(
            text =>
            {
                calls.Add(text);
                return new OpirScore(0.05f, "toxicity", [0.05f, 0.01f, 0.01f, 0.01f, 0.01f, 0.01f]);
            },
            Labels,
            WindowingTestHelpers.CountWords,
            prefixTokenCount: 30,
            new OpirSafetyOptions { ModelPath = "m", TokenizerPath = "t", PrefixPath = "p", MaxWindows = 0 });

        var result = await rule.EvaluateAsync(new GuardrailContext { Text = WindowingTestHelpers.Words(40_000), Phase = GuardrailPhase.Input });

        result.IsBlocked.Should().BeFalse();
        calls.Should().HaveCountGreaterThan(32, "the default limit does not apply when MaxWindows is 0");
    }

    [Fact]
    public void ShouldReleaseThePooledSessionOnce_WhenDisposedTwice()
    {
        // the session is shared process-wide and reference-counted, so a second release would free it
        // under other rules still holding it
        var session = new CountingDisposable();
        var rule = CreateRuleWithSession(session);

        rule.Dispose();
        rule.Dispose();

        session.DisposeCount.Should().Be(1);
    }

    [Fact]
    public void ShouldReleaseThePooledSessionOnce_WhenDisposedFromSeveralThreadsAtOnce()
    {
        var counts = CountingDisposable.DisposeConcurrently(CreateRuleWithSession);

        counts.Should().OnlyContain(count => count == 1);
    }

    [Fact]
    public async Task ShouldThrowObjectDisposed_WhenEvaluatedAfterDispose()
    {
        var rule = CreateRuleWithSession(new CountingDisposable());
        rule.Dispose();

        var act = async () => await rule.EvaluateAsync(new GuardrailContext { Text = "hello", Phase = GuardrailPhase.Input });

        await act.Should().ThrowAsync<ObjectDisposedException>();
    }

    [Fact]
    public async Task ShouldReturnPassed_WhenTextIsEmpty()
    {
        var rule = CreateRuleWithoutSession();
        var ctx = new GuardrailContext { Text = "", Phase = GuardrailPhase.Input };
        var result = await rule.EvaluateAsync(ctx);

        result.IsBlocked.Should().BeFalse("empty text must pass without invoking the classifier");
    }

    [Fact]
    public async Task ShouldReturnPassed_WhenTextIsWhitespace()
    {
        var rule = CreateRuleWithoutSession();
        var ctx = new GuardrailContext { Text = "   ", Phase = GuardrailPhase.Input };
        var result = await rule.EvaluateAsync(ctx);

        result.IsBlocked.Should().BeFalse("whitespace-only text must pass without invoking the classifier");
    }

    // windowing: input longer than one window is classified window by window (fake classifier that
    // scores windows by marker words, and one token per word; a 30-token label prefix leaves a
    // 481-token text budget out of the default 512)

    [Fact]
    public void ShouldHaveWindowingDefaults_WhenOptionsAreNotSet()
    {
        var options = new OpirSafetyOptions { ModelPath = "m", TokenizerPath = "t", PrefixPath = "p" };

        options.WindowSize.Should().Be(512);
        options.WindowOverlap.Should().Be(128);
        options.MaxWindows.Should().Be(32);
    }

    [Fact]
    public async Task ShouldClassifyWholeTextInOneCall_WhenTextFitsInTheTextBudget()
    {
        var text = WindowingTestHelpers.WordsWithMarker(481, 400, "TOXIC");
        var calls = new List<string>();
        var rule = CreateWindowedRule(calls);

        var result = await rule.EvaluateAsync(new GuardrailContext { Text = text, Phase = GuardrailPhase.Input });

        calls.Should().Equal([text], "text that fits the model's text budget must be classified exactly as before, in one call");
        result.IsBlocked.Should().BeTrue();
        result.Metadata.Should().NotContainKey("windowCount");
    }

    [Fact]
    public async Task ShouldReportWorstWindowScores_WhenInputIsSplitIntoWindows()
    {
        var words = WindowingTestHelpers.Words(3000).Split(' ');
        words[200] = "TOXIC";
        words[2600] = "VIOLENT";
        var calls = new List<string>();
        var rule = CreateWindowedRule(calls);

        var result = await rule.EvaluateAsync(new GuardrailContext { Text = string.Join(' ', words), Phase = GuardrailPhase.Input });

        result.IsBlocked.Should().BeTrue();
        result.Severity.Should().Be(GuardrailSeverity.High);
        result.Metadata!["label"].Should().Be("violence", "the highest-scoring window is reported");
        result.Metadata["confidence"].Should().Be(0.9f);
        var scores = (Dictionary<string, object>)result.Metadata["scores"];
        scores["violence"].Should().Be(0.9f);
        scores["toxicity"].Should().Be(0.01f, "per-label scores come from the reported window");
        calls.Should().OnlyContain(window => WindowingTestHelpers.CountWords(window) <= 481);
    }

    [Fact]
    public async Task ShouldBlockAsTooLong_WhenInputNeedsMoreThanMaxWindows()
    {
        var rule = new OpirSafetyRule(
            WindowingTestHelpers.NotCalled<OpirScore>,
            Labels,
            WindowingTestHelpers.CountWords,
            prefixTokenCount: 30,
            new OpirSafetyOptions { ModelPath = "m", TokenizerPath = "t", PrefixPath = "p", MaxWindows = 4 });

        var result = await rule.EvaluateAsync(new GuardrailContext { Text = WindowingTestHelpers.Words(5000), Phase = GuardrailPhase.Input });

        result.IsBlocked.Should().BeTrue("input that cannot be scanned completely must not pass");
        result.Severity.Should().Be(GuardrailSeverity.Medium);
        result.Reason.Should().Contain(nameof(OpirSafetyOptions));
        result.Metadata!["inputTooLong"].Should().Be(true);
    }

    [Fact]
    public void ShouldThrow_WhenWindowOverlapIsNotSmallerThanWindowSize()
    {
        var modelTemp = Path.GetTempFileName();
        var tokenizerTemp = Path.GetTempFileName();
        var prefixTemp = Path.GetTempFileName();
        try
        {
            var act = () => new OpirSafetyRule(new OpirSafetyOptions
            {
                ModelPath = modelTemp,
                TokenizerPath = tokenizerTemp,
                PrefixPath = prefixTemp,
                WindowSize = 128,
                WindowOverlap = 128
            });

            act.Should().Throw<ArgumentOutOfRangeException>().WithMessage("*WindowOverlap*");
        }
        finally
        {
            File.Delete(modelTemp);
            File.Delete(tokenizerTemp);
            File.Delete(prefixTemp);
        }
    }

    private static OpirSafetyRule CreateRuleWithSession(IDisposable session) =>
        new(WindowingTestHelpers.NotCalled<OpirScore>, Labels, WindowingTestHelpers.CountWords, prefixTokenCount: 30,
            new OpirSafetyOptions { ModelPath = "m", TokenizerPath = "t", PrefixPath = "p" }, session);

    private static OpirSafetyRule CreateWindowedRule(List<string> calls) =>
        new(
            text =>
            {
                calls.Add(text);
                if (text.Contains("VIOLENT"))
                    return new OpirScore(0.9f, "violence", [0.01f, 0.01f, 0.9f, 0.01f, 0.01f, 0.01f]);
                if (text.Contains("TOXIC"))
                    return new OpirScore(0.7f, "toxicity", [0.7f, 0.01f, 0.01f, 0.01f, 0.01f, 0.01f]);
                return new OpirScore(0.05f, "toxicity", [0.05f, 0.01f, 0.01f, 0.01f, 0.01f, 0.01f]);
            },
            Labels,
            WindowingTestHelpers.CountWords,
            prefixTokenCount: 30,
            new OpirSafetyOptions { ModelPath = "m", TokenizerPath = "t", PrefixPath = "p" });
}
