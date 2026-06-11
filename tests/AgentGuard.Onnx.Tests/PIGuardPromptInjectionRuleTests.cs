using AgentGuard.Core.Abstractions;
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
        new(null!, new PIGuardPromptInjectionOptions
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
}
