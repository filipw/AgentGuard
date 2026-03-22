using AgentGuard.Core.Abstractions;
using AgentGuard.Onnx;
using FluentAssertions;
using Xunit;

namespace AgentGuard.Onnx.Tests;

/// <summary>
/// Unit tests for <see cref="DefenderPromptInjectionRule"/> and the internal
/// <see cref="DefenderModelSession"/> helpers.
/// </summary>
public class DefenderPromptInjectionRuleTests
{
    // -----------------------------------------------------------------------
    // Sigmoid tests — DefenderModelSession.Sigmoid is internal static
    // -----------------------------------------------------------------------

    [Fact]
    public void Sigmoid_ShouldReturnHalf_WhenInputIsZero()
    {
        DefenderModelSession.Sigmoid(0f).Should().BeApproximately(0.5f, 1e-6f);
    }

    [Fact]
    public void Sigmoid_ShouldReturnNearOne_WhenInputIsLargePositive()
    {
        DefenderModelSession.Sigmoid(10f).Should().BeGreaterThan(0.9999f);
    }

    [Fact]
    public void Sigmoid_ShouldReturnNearZero_WhenInputIsLargeNegative()
    {
        DefenderModelSession.Sigmoid(-10f).Should().BeLessThan(0.0001f);
    }

    [Fact]
    public void Sigmoid_ShouldHandleExtremeValues_WhenInputIsVeryLarge()
    {
        var result = DefenderModelSession.Sigmoid(1000f);
        result.Should().NotBe(float.NaN);
        result.Should().NotBe(float.PositiveInfinity);
    }

    [Fact]
    public void Sigmoid_ShouldHandleExtremeValues_WhenInputIsVeryNegative()
    {
        var result = DefenderModelSession.Sigmoid(-1000f);
        result.Should().NotBe(float.NaN);
        result.Should().BeGreaterOrEqualTo(0f);
    }

    // -----------------------------------------------------------------------
    // Rule properties
    // -----------------------------------------------------------------------

    [Fact]
    public void ShouldHaveCorrectName()
    {
        // Use a mock session to avoid needing model files
        var rule = CreateRuleWithMockSession(0.5f);
        rule.Name.Should().Be("defender-prompt-injection");
    }

    [Fact]
    public void ShouldHaveInputPhase()
    {
        var rule = CreateRuleWithMockSession(0.5f);
        rule.Phase.Should().Be(GuardrailPhase.Input);
    }

    [Fact]
    public void ShouldHaveOrder11()
    {
        var rule = CreateRuleWithMockSession(0.5f);
        rule.Order.Should().Be(11);
    }

    // -----------------------------------------------------------------------
    // Options validation
    // -----------------------------------------------------------------------

    [Theory]
    [InlineData(-0.1f)]
    [InlineData(1.1f)]
    [InlineData(-1f)]
    [InlineData(2f)]
    public void ShouldThrow_WhenThresholdIsOutOfRange(float threshold)
    {
        var act = () => new DefenderPromptInjectionRule(new DefenderPromptInjectionOptions
        {
            Threshold = threshold,
            ModelPath = "/nonexistent/model.onnx",
            VocabPath = "/nonexistent/vocab.txt"
        });

        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Fact]
    public void ShouldThrow_WhenCustomModelPathDoesNotExist()
    {
        var act = () => new DefenderPromptInjectionRule(new DefenderPromptInjectionOptions
        {
            ModelPath = "/nonexistent/path/model.onnx"
        });

        act.Should().Throw<FileNotFoundException>();
    }

    [Fact]
    public void ShouldThrow_WhenCustomVocabPathDoesNotExist()
    {
        // Create a temp model file but point vocab to nonexistent
        var tempModel = Path.GetTempFileName();
        try
        {
            var act = () => new DefenderPromptInjectionRule(new DefenderPromptInjectionOptions
            {
                ModelPath = tempModel,
                VocabPath = "/nonexistent/path/vocab.txt"
            });

            act.Should().Throw<FileNotFoundException>();
        }
        finally
        {
            File.Delete(tempModel);
        }
    }

    // -----------------------------------------------------------------------
    // EvaluateAsync behavior (with mock session)
    // -----------------------------------------------------------------------

    [Fact]
    public async Task ShouldPass_WhenTextIsEmpty()
    {
        var rule = CreateRuleWithMockSession(0.5f);

        var ctx = new GuardrailContext { Text = "", Phase = GuardrailPhase.Input };
        var result = await rule.EvaluateAsync(ctx);

        result.IsBlocked.Should().BeFalse();
    }

    [Fact]
    public async Task ShouldPass_WhenTextIsWhitespace()
    {
        var rule = CreateRuleWithMockSession(0.5f);

        var ctx = new GuardrailContext { Text = "   ", Phase = GuardrailPhase.Input };
        var result = await rule.EvaluateAsync(ctx);

        result.IsBlocked.Should().BeFalse();
    }

    // -----------------------------------------------------------------------
    // Default options
    // -----------------------------------------------------------------------

    [Fact]
    public void DefaultOptions_ShouldHaveCorrectDefaults()
    {
        var options = new DefenderPromptInjectionOptions();

        options.Threshold.Should().Be(0.5f);
        options.MaxTokenLength.Should().Be(256);
        options.IncludeConfidence.Should().BeTrue();
        options.ModelPath.Should().BeNull();
        options.VocabPath.Should().BeNull();
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// <summary>
    /// Creates a rule with a fake session that always returns a fixed score.
    /// Uses the internal constructor to bypass model file requirements.
    /// </summary>
    private static DefenderPromptInjectionRule CreateRuleWithMockSession(float threshold)
    {
        // We can't create a real DefenderModelSession without model files,
        // but we can test properties via the internal constructor with null session
        // For property tests, we use a wrapper approach
        return new DefenderPromptInjectionRule(
            null!,
            new DefenderPromptInjectionOptions { Threshold = threshold });
    }
}
