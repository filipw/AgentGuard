using AgentGuard.Core.Abstractions;
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
    // Softmax tests — OnnxModelSession.Softmax is internal static, accessible
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
    // Rule property tests — use the internal constructor with a null session
    // guard: we build a minimal fake by supplying null and relying on the fact
    // that property accessors do not touch the session.
    // -----------------------------------------------------------------------

    private static OnnxPromptInjectionRule CreateRuleWithoutSession() =>
        new(null!, new OnnxPromptInjectionOptions
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
    // Options validation tests — exercise the public constructor which validates
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
    // EvaluateAsync behaviour tests — use the internal constructor so no
    // real model files are required. The session is passed as null; we only
    // exercise code paths that return early (null/whitespace text).
    // -----------------------------------------------------------------------

    [Fact]
    public async Task ShouldReturnPassed_WhenTextIsEmpty()
    {
        var rule = new OnnxPromptInjectionRule(null!, new OnnxPromptInjectionOptions
        {
            ModelPath = "/nonexistent/model.onnx",
            TokenizerPath = "/nonexistent/tokenizer.spm"
        });

        var ctx = new GuardrailContext { Text = "", Phase = GuardrailPhase.Input };
        var result = await rule.EvaluateAsync(ctx);

        result.IsBlocked.Should().BeFalse("empty text must pass without invoking the classifier");
    }

    [Fact]
    public async Task ShouldReturnPassed_WhenTextIsWhitespace()
    {
        var rule = new OnnxPromptInjectionRule(null!, new OnnxPromptInjectionOptions
        {
            ModelPath = "/nonexistent/model.onnx",
            TokenizerPath = "/nonexistent/tokenizer.spm"
        });

        var ctx = new GuardrailContext { Text = "   ", Phase = GuardrailPhase.Input };
        var result = await rule.EvaluateAsync(ctx);

        result.IsBlocked.Should().BeFalse("whitespace-only text must pass without invoking the classifier");
    }
}
