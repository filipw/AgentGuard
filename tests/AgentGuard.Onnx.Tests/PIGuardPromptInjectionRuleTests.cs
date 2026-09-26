using AgentGuard.Core.Abstractions;
using Kyoto;
using FluentAssertions;
using Xunit;

namespace AgentGuard.Onnx.Tests;

/// <summary>
/// Unit tests for <see cref="PIGuardPromptInjectionRule"/> that can be exercised without real
/// model files (properties, options validation, early-return behaviour).
/// </summary>
public class PIGuardPromptInjectionRuleTests
{
    private static PIGuardPromptInjectionRule CreateRuleWithoutSession() =>
        new(WindowingTestHelpers.NotCalled<float>, WindowingTestHelpers.CountWords, new PIGuardPromptInjectionOptions
        {
            ModelPath = "/nonexistent/model.onnx",
            TokenizerPath = "/nonexistent/spm.model"
        });

    [Fact]
    public void ShouldHaveCorrectName()
    {
        var rule = CreateRuleWithoutSession();
        rule.Name.Should().Be("piguard-prompt-injection");
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
        rule.Order.Should().Be(12);
    }

    [Fact]
    public void ShouldDefaultThresholdToZeroPointNine()
    {
        var options = new PIGuardPromptInjectionOptions
        {
            ModelPath = "/nonexistent/model.onnx",
            TokenizerPath = "/nonexistent/spm.model"
        };
        options.Threshold.Should().Be(0.9f);
    }

    [Fact]
    public void ShouldThrow_WhenModelPathIsNull()
    {
#pragma warning disable CS9035 // required member must be set
        var act = () => new PIGuardPromptInjectionRule(new PIGuardPromptInjectionOptions
        {
            ModelPath = null!,
            TokenizerPath = "/nonexistent/spm.model"
        });
#pragma warning restore CS9035

        act.Should().Throw<ArgumentException>().WithMessage("*ModelPath*");
    }

    [Fact]
    public void ShouldThrow_WhenModelPathDoesNotExist()
    {
        var act = () => new PIGuardPromptInjectionRule(new PIGuardPromptInjectionOptions
        {
            ModelPath = "/nonexistent/does-not-exist.onnx",
            TokenizerPath = "/nonexistent/spm.model"
        });

        act.Should().Throw<FileNotFoundException>().WithMessage("*does-not-exist.onnx*");
    }

    [Fact]
    public void ShouldThrow_WhenTokenizerPathDoesNotExist()
    {
        var modelTemp = Path.GetTempFileName();
        try
        {
            var act = () => new PIGuardPromptInjectionRule(new PIGuardPromptInjectionOptions
            {
                ModelPath = modelTemp,
                TokenizerPath = "/nonexistent/spm.model"
            });

            act.Should().Throw<FileNotFoundException>().WithMessage("*spm.model*");
        }
        finally
        {
            File.Delete(modelTemp);
        }
    }

    [Fact]
    public void ShouldThrow_WhenThresholdIsAboveOne()
    {
        var modelTemp = Path.GetTempFileName();
        var tokenizerTemp = Path.GetTempFileName();
        try
        {
            var act = () => new PIGuardPromptInjectionRule(new PIGuardPromptInjectionOptions
            {
                ModelPath = modelTemp,
                TokenizerPath = tokenizerTemp,
                Threshold = 1.1f
            });

            act.Should().Throw<ArgumentOutOfRangeException>().WithMessage("*Threshold*");
        }
        finally
        {
            File.Delete(modelTemp);
            File.Delete(tokenizerTemp);
        }
    }

    [Theory]
    [InlineData(-0.1f)]
    [InlineData(float.NaN)]
    [InlineData(float.PositiveInfinity)]
    public void ShouldThrow_WhenThresholdIsNotANumberBetweenZeroAndOne(float threshold)
    {
        // checked before any model file is opened
        var act = () => new PIGuardPromptInjectionRule(new PIGuardPromptInjectionOptions
        {
            ModelPath = "/nonexistent/model.onnx",
            TokenizerPath = "/nonexistent/spm.model",
            Threshold = threshold
        });

        act.Should().Throw<ArgumentOutOfRangeException>().WithMessage("*Threshold*");
    }

    [Theory]
    [InlineData(2)]
    [InlineData(0)]
    public void ShouldThrow_WhenMaxTokenLengthLeavesNoRoomForInput(int maxTokenLength)
    {
        var act = () => new PIGuardPromptInjectionRule(new PIGuardPromptInjectionOptions
        {
            ModelPath = "/nonexistent/model.onnx",
            TokenizerPath = "/nonexistent/spm.model",
            MaxTokenLength = maxTokenLength
        });

        act.Should().Throw<ArgumentOutOfRangeException>().WithMessage("*MaxTokenLength*");
    }

    [Fact]
    public async Task ShouldScanEveryWindow_WhenMaxWindowsIsZero()
    {
        // 0 means no limit
        var calls = new List<string>();
        var rule = new PIGuardPromptInjectionRule(
            text =>
            {
                calls.Add(text);
                return 0.02f;
            },
            WindowingTestHelpers.CountWords,
            new PIGuardPromptInjectionOptions { ModelPath = "m", TokenizerPath = "t", MaxWindows = 0 });

        var result = await rule.EvaluateAsync(new GuardrailContext { Text = WindowingTestHelpers.Words(40_000), Phase = GuardrailPhase.Input });

        result.IsBlocked.Should().BeFalse();
        calls.Should().HaveCountGreaterThan(32, "the default limit does not apply when MaxWindows is 0");
    }

    [Fact]
    public void ShouldReleaseTheSessionOnce_WhenDisposedTwice()
    {
        var session = new CountingDisposable();
        var rule = CreateRuleWithSession(session);

        rule.Dispose();
        rule.Dispose();

        session.DisposeCount.Should().Be(1);
    }

    [Fact]
    public void ShouldReleaseTheSessionOnce_WhenDisposedFromSeveralThreadsAtOnce()
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
    // flags any window containing INJECT, and one token per word)

    [Fact]
    public void ShouldHaveWindowingDefaults_WhenOptionsAreNotSet()
    {
        var options = new PIGuardPromptInjectionOptions { ModelPath = "m", TokenizerPath = "t" };

        options.WindowSize.Should().Be(510);
        options.WindowOverlap.Should().Be(128);
        options.MaxWindows.Should().Be(32);
    }

    [Fact]
    public async Task ShouldClassifyWholeTextInOneCall_WhenTextFitsInOneWindow()
    {
        var text = WindowingTestHelpers.WordsWithMarker(300, 250, "INJECT");
        var calls = new List<string>();
        var rule = CreateWindowedRule(calls);

        var result = await rule.EvaluateAsync(new GuardrailContext { Text = text, Phase = GuardrailPhase.Input });

        calls.Should().Equal([text], "text that fits the model's input must be classified exactly as before, in one call");
        result.IsBlocked.Should().BeTrue();
        result.Reason.Should().NotContain("window");
        result.Metadata.Should().NotContainKey("windowCount");
    }

    [Fact]
    public async Task ShouldBlock_WhenInjectionIsBeyondTheModelInputLength()
    {
        var text = WindowingTestHelpers.WordsWithMarker(3000, 2500, "INJECT");
        var calls = new List<string>();
        var rule = CreateWindowedRule(calls);

        var result = await rule.EvaluateAsync(new GuardrailContext { Text = text, Phase = GuardrailPhase.Input });

        result.IsBlocked.Should().BeTrue("text past the model's input length must still be classified");
        result.Reason.Should().Contain("window");
        result.Metadata!["model"].Should().Be("piguard-deberta-v3");
        text.Substring((int)result.Metadata["windowStart"], (int)result.Metadata["windowLength"]).Should().Contain("INJECT");
        calls.Should().OnlyContain(window => WindowingTestHelpers.CountWords(window) <= 510);
    }

    [Fact]
    public async Task ShouldPass_WhenNoWindowBlocks()
    {
        var calls = new List<string>();
        var rule = CreateWindowedRule(calls);

        var result = await rule.EvaluateAsync(new GuardrailContext { Text = WindowingTestHelpers.Words(3000), Phase = GuardrailPhase.Input });

        result.IsBlocked.Should().BeFalse();
        calls.SelectMany(window => window.Split(' ')).Distinct().Should().HaveCount(3000, "no word may go unclassified");
    }

    private static PIGuardPromptInjectionRule CreateRuleWithSession(IDisposable session) =>
        new(WindowingTestHelpers.NotCalled<float>, WindowingTestHelpers.CountWords,
            new PIGuardPromptInjectionOptions { ModelPath = "m", TokenizerPath = "t" }, session);

    private static PIGuardPromptInjectionRule CreateWindowedRule(List<string> calls) =>
        new(
            text =>
            {
                calls.Add(text);
                return text.Contains("INJECT") ? 0.97f : 0.02f;
            },
            WindowingTestHelpers.CountWords,
            new PIGuardPromptInjectionOptions { ModelPath = "m", TokenizerPath = "t" });
}
