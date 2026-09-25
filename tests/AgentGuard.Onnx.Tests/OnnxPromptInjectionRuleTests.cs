using AgentGuard.Core.Abstractions;
using Kyoto;
using AgentGuard.Onnx;
using FluentAssertions;
using Xunit;

namespace AgentGuard.Onnx.Tests;

/// <summary>
/// Unit tests for <see cref="OnnxPromptInjectionRule"/> and the internal
/// <see cref="OnnxModelSession"/> helpers that can be exercised without real model files.
/// </summary>
public class OnnxPromptInjectionRuleTests
{
    // -----------------------------------------------------------------------
    // Softmax tests - OnnxModelSession.Softmax is internal static, accessible
    // via InternalsVisibleTo.
    // -----------------------------------------------------------------------

    [Fact]
    public void ShouldReturnEqualProbabilities_WhenLogitsAreEqual()
    {
        var (safe, injection) = OnnxModelSession.Softmax(0f, 0f);

        safe.Should().BeApproximately(0.5f, 1e-6f);
        injection.Should().BeApproximately(0.5f, 1e-6f);
    }

    [Fact]
    public void ShouldReturnHighProbForFirstClass_WhenFirstLogitIsLarger()
    {
        var (safe, injection) = OnnxModelSession.Softmax(10f, 0f);

        safe.Should().BeGreaterThan(0.99f, "a large safe logit should yield near-1 safe probability");
        injection.Should().BeLessThan(0.01f);
        (safe + injection).Should().BeApproximately(1f, 1e-6f);
    }

    [Fact]
    public void ShouldReturnHighProbForSecondClass_WhenSecondLogitIsLarger()
    {
        var (safe, injection) = OnnxModelSession.Softmax(0f, 10f);

        injection.Should().BeGreaterThan(0.99f, "a large injection logit should yield near-1 injection probability");
        safe.Should().BeLessThan(0.01f);
        (safe + injection).Should().BeApproximately(1f, 1e-6f);
    }

    [Fact]
    public void ShouldHandleNegativeLogits_WhenBothNegative()
    {
        var (safe, injection) = OnnxModelSession.Softmax(-2f, -1f);

        safe.Should().BeGreaterThan(0f);
        injection.Should().BeGreaterThan(0f);
        (safe + injection).Should().BeApproximately(1f, 1e-6f,
            "probabilities must sum to 1.0 regardless of sign");
    }

    [Fact]
    public void ShouldHandleLargeLogits_WithoutOverflow()
    {
        var (safe, injection) = OnnxModelSession.Softmax(1000f, 999f);

        float.IsNaN(safe).Should().BeFalse("softmax should not produce NaN for large inputs");
        float.IsNaN(injection).Should().BeFalse("softmax should not produce NaN for large inputs");
        float.IsInfinity(safe).Should().BeFalse("softmax should not produce Infinity for large inputs");
        float.IsInfinity(injection).Should().BeFalse("softmax should not produce Infinity for large inputs");
        (safe + injection).Should().BeApproximately(1f, 1e-6f);
    }

    // -----------------------------------------------------------------------
    // Rule property tests - use the internal constructor with a classifier that
    // must never be called: property accessors do not touch the model.
    // -----------------------------------------------------------------------

    private static OnnxPromptInjectionRule CreateRuleWithoutSession() =>
        new(WindowingTestHelpers.NotCalled<float>, WindowingTestHelpers.CountWords, new OnnxPromptInjectionOptions
        {
            ModelPath = "/nonexistent/model.onnx",
            TokenizerPath = "/nonexistent/tokenizer.spm"
        });

    [Fact]
    public void ShouldHaveCorrectName()
    {
        var rule = CreateRuleWithoutSession();
        rule.Name.Should().Be("onnx-prompt-injection");
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

    // -----------------------------------------------------------------------
    // Options validation tests - exercise the public constructor which validates
    // paths and threshold before touching the filesystem / ONNX runtime.
    // -----------------------------------------------------------------------

    [Fact]
    public void ShouldThrow_WhenModelPathIsNull()
    {
#pragma warning disable CS9035 // required member must be set
        var act = () => new OnnxPromptInjectionRule(new OnnxPromptInjectionOptions
        {
            ModelPath = null!,
            TokenizerPath = "/nonexistent/tokenizer.spm"
        });
#pragma warning restore CS9035

        act.Should().Throw<ArgumentException>()
            .WithMessage("*ModelPath*");
    }

    [Fact]
    public void ShouldThrow_WhenModelPathIsEmpty()
    {
        var act = () => new OnnxPromptInjectionRule(new OnnxPromptInjectionOptions
        {
            ModelPath = "",
            TokenizerPath = "/nonexistent/tokenizer.spm"
        });

        act.Should().Throw<ArgumentException>()
            .WithMessage("*ModelPath*");
    }

    [Fact]
    public void ShouldThrow_WhenModelPathDoesNotExist()
    {
        var act = () => new OnnxPromptInjectionRule(new OnnxPromptInjectionOptions
        {
            ModelPath = "/nonexistent/does-not-exist.onnx",
            TokenizerPath = "/nonexistent/tokenizer.spm"
        });

        act.Should().Throw<FileNotFoundException>()
            .WithMessage("*does-not-exist.onnx*");
    }

    [Fact]
    public void ShouldThrow_WhenTokenizerPathIsNull()
    {
        // ModelPath must point to a real file so that validation reaches the TokenizerPath check.
        var modelTemp = Path.GetTempFileName();
        try
        {
#pragma warning disable CS9035 // required member must be set
            var act = () => new OnnxPromptInjectionRule(new OnnxPromptInjectionOptions
            {
                ModelPath = modelTemp,
                TokenizerPath = null!
            });
#pragma warning restore CS9035

            act.Should().Throw<ArgumentException>()
                .WithMessage("*TokenizerPath*");
        }
        finally
        {
            File.Delete(modelTemp);
        }
    }

    [Fact]
    public void ShouldThrow_WhenTokenizerPathIsEmpty()
    {
        // ModelPath must point to a real file so that validation reaches the TokenizerPath check.
        var modelTemp = Path.GetTempFileName();
        try
        {
            var act = () => new OnnxPromptInjectionRule(new OnnxPromptInjectionOptions
            {
                ModelPath = modelTemp,
                TokenizerPath = ""
            });

            act.Should().Throw<ArgumentException>()
                .WithMessage("*TokenizerPath*");
        }
        finally
        {
            File.Delete(modelTemp);
        }
    }

    [Fact]
    public void ShouldThrow_WhenTokenizerPathDoesNotExist()
    {
        // Create a real temp file so ModelPath validation passes, but TokenizerPath doesn't exist.
        var tempFile = Path.GetTempFileName();
        try
        {
            var act = () => new OnnxPromptInjectionRule(new OnnxPromptInjectionOptions
            {
                ModelPath = tempFile,
                TokenizerPath = "/nonexistent/tokenizer.spm"
            });

            act.Should().Throw<FileNotFoundException>()
                .WithMessage("*tokenizer*");
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [Fact]
    public void ShouldThrow_WhenThresholdIsAboveOne()
    {
        // Both files must exist so validation reaches the threshold check.
        var modelTemp = Path.GetTempFileName();
        var tokenizerTemp = Path.GetTempFileName();
        try
        {
            var act = () => new OnnxPromptInjectionRule(new OnnxPromptInjectionOptions
            {
                ModelPath = modelTemp,
                TokenizerPath = tokenizerTemp,
                Threshold = 1.1f
            });

            act.Should().Throw<ArgumentOutOfRangeException>()
                .WithMessage("*Threshold*");
        }
        finally
        {
            File.Delete(modelTemp);
            File.Delete(tokenizerTemp);
        }
    }

    [Fact]
    public void ShouldThrow_WhenThresholdIsBelowZero()
    {
        // Both files must exist so validation reaches the threshold check.
        var modelTemp = Path.GetTempFileName();
        var tokenizerTemp = Path.GetTempFileName();
        try
        {
            var act = () => new OnnxPromptInjectionRule(new OnnxPromptInjectionOptions
            {
                ModelPath = modelTemp,
                TokenizerPath = tokenizerTemp,
                Threshold = -0.1f
            });

            act.Should().Throw<ArgumentOutOfRangeException>()
                .WithMessage("*Threshold*");
        }
        finally
        {
            File.Delete(modelTemp);
            File.Delete(tokenizerTemp);
        }
    }

    // -----------------------------------------------------------------------
    // EvaluateAsync behaviour tests - use the internal constructor so no
    // real model files are required. The classifier must never be called; we
    // only exercise code paths that return early (null/whitespace text).
    // -----------------------------------------------------------------------

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
        var options = new OnnxPromptInjectionOptions { ModelPath = "m", TokenizerPath = "t" };

        options.WindowSize.Should().Be(510);
        options.WindowOverlap.Should().Be(128);
        options.MaxWindows.Should().Be(32);
    }

    [Fact]
    public async Task ShouldClassifyWholeTextInOneCall_WhenTextFitsInOneWindow()
    {
        var text = WindowingTestHelpers.WordsWithMarker(510, 500, "INJECT");
        var calls = new List<string>();
        var rule = CreateWindowedRule(calls);

        var result = await rule.EvaluateAsync(new GuardrailContext { Text = text, Phase = GuardrailPhase.Input });

        calls.Should().Equal([text], "text that fits the model's input must be classified exactly as before, in one call");
        result.IsBlocked.Should().BeTrue();
        result.Metadata.Should().NotContainKey("windowCount");
    }

    [Fact]
    public async Task ShouldBlock_WhenInjectionIsBeyondTheModelInputLength()
    {
        var text = WindowingTestHelpers.WordsWithMarker(2000, 1800, "INJECT");
        var calls = new List<string>();
        var rule = CreateWindowedRule(calls);

        var result = await rule.EvaluateAsync(new GuardrailContext { Text = text, Phase = GuardrailPhase.Input });

        result.IsBlocked.Should().BeTrue("text past the model's input length must still be classified");
        result.Severity.Should().Be(GuardrailSeverity.Critical);
        result.Metadata!["confidence"].Should().Be(0.99f);
        ((int)result.Metadata["windowCount"]).Should().Be(calls.Count);
        text.Substring((int)result.Metadata["windowStart"], (int)result.Metadata["windowLength"]).Should().Contain("INJECT");
        calls.Should().OnlyContain(window => WindowingTestHelpers.CountWords(window) <= 510);
    }

    [Fact]
    public async Task ShouldBlockAsTooLong_WhenInputNeedsMoreThanMaxWindows()
    {
        var rule = new OnnxPromptInjectionRule(
            WindowingTestHelpers.NotCalled<float>,
            WindowingTestHelpers.CountWords,
            new OnnxPromptInjectionOptions { ModelPath = "m", TokenizerPath = "t", MaxWindows = 2 });

        var result = await rule.EvaluateAsync(new GuardrailContext { Text = WindowingTestHelpers.Words(2000), Phase = GuardrailPhase.Input });

        result.IsBlocked.Should().BeTrue("input that cannot be scanned completely must not pass");
        result.Severity.Should().Be(GuardrailSeverity.Medium);
        result.Reason.Should().Contain(nameof(OnnxPromptInjectionOptions)).And.Contain("MaxWindows");
        result.Metadata!["inputTooLong"].Should().Be(true);
    }

    [Theory]
    [InlineData(0, 0, 32)]
    [InlineData(128, 128, 32)]
    [InlineData(510, -1, 32)]
    [InlineData(510, 128, -1)]
    public void ShouldThrow_WhenWindowSettingsAreInvalid(int windowSize, int windowOverlap, int maxWindows)
    {
        // both files must exist so validation reaches the window checks
        var modelTemp = Path.GetTempFileName();
        var tokenizerTemp = Path.GetTempFileName();
        try
        {
            var act = () => new OnnxPromptInjectionRule(new OnnxPromptInjectionOptions
            {
                ModelPath = modelTemp,
                TokenizerPath = tokenizerTemp,
                WindowSize = windowSize,
                WindowOverlap = windowOverlap,
                MaxWindows = maxWindows
            });

            act.Should().Throw<ArgumentOutOfRangeException>().WithMessage("*Window*");
        }
        finally
        {
            File.Delete(modelTemp);
            File.Delete(tokenizerTemp);
        }
    }

    private static OnnxPromptInjectionRule CreateWindowedRule(List<string> calls) =>
        new(
            text =>
            {
                calls.Add(text);
                return text.Contains("INJECT") ? 0.99f : 0.01f;
            },
            WindowingTestHelpers.CountWords,
            new OnnxPromptInjectionOptions { ModelPath = "m", TokenizerPath = "t" });
}
