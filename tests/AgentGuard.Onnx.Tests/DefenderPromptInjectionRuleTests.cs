using AgentGuard.Core.Abstractions;
using AgentGuard.Onnx;
using FluentAssertions;
using Xunit;

namespace AgentGuard.Onnx.Tests;

/// <summary>
/// Unit tests for <see cref="DefenderPromptInjectionRule"/> and the internal
/// <see cref="DefenderModelSession"/> helpers. These do not load the real model -
/// see <c>DefenderPromptInjectionE2ETests</c> for tests against the bundled model.
/// </summary>
public class DefenderPromptInjectionRuleTests
{
    // -----------------------------------------------------------------------
    // Sigmoid tests - DefenderModelSession.Sigmoid is internal static
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
    // Multi-head decision rule - the core logic, testable without a model
    // -----------------------------------------------------------------------

    [Fact]
    public void ShouldBlock_WhenMainHighAndAuxLow()
    {
        // classic injection: high main, low aux (not directed at a human reader)
        var score = new DefenderScore(Main: 0.96f, Aux: 0.10f);
        DefenderPromptInjectionRule.ShouldBlock(score, 0.5f, 0.64f).Should().BeTrue();
    }

    [Fact]
    public void ShouldNotBlock_WhenMainHighButAuxAlsoHigh()
    {
        // imperative-but-benign ("show me my orders"): the aux veto rescues it
        var score = new DefenderScore(Main: 0.90f, Aux: 0.70f);
        DefenderPromptInjectionRule.ShouldBlock(score, 0.5f, 0.64f).Should().BeFalse();
    }

    [Fact]
    public void ShouldNotBlock_WhenMainBelowThreshold()
    {
        var score = new DefenderScore(Main: 0.40f, Aux: 0.10f);
        DefenderPromptInjectionRule.ShouldBlock(score, 0.5f, 0.64f).Should().BeFalse();
    }

    [Fact]
    public void ShouldBlock_WhenAuxExactlyAtThreshold_IsVetoed()
    {
        // aux veto triggers at aux >= auxThreshold, so aux == threshold rescues
        var score = new DefenderScore(Main: 0.90f, Aux: 0.64f);
        DefenderPromptInjectionRule.ShouldBlock(score, 0.5f, 0.64f).Should().BeFalse();
    }

    [Fact]
    public void ShouldBlock_WhenMainExactlyAtThreshold()
    {
        var score = new DefenderScore(Main: 0.50f, Aux: 0.10f);
        DefenderPromptInjectionRule.ShouldBlock(score, 0.5f, 0.64f).Should().BeTrue();
    }

    // -----------------------------------------------------------------------
    // Rule properties
    // -----------------------------------------------------------------------

    [Fact]
    public void ShouldHaveCorrectName()
    {
        var rule = CreateRuleWithMockSession();
        rule.Name.Should().Be("defender-prompt-injection");
    }

    [Fact]
    public void ShouldHaveInputPhase()
    {
        var rule = CreateRuleWithMockSession();
        rule.Phase.Should().Be(GuardrailPhase.Input);
    }

    [Fact]
    public void ShouldHaveOrder11()
    {
        var rule = CreateRuleWithMockSession();
        rule.Order.Should().Be(11);
    }

    // -----------------------------------------------------------------------
    // Options validation
    // -----------------------------------------------------------------------

    [Theory]
    [InlineData(-0.1f)]
    [InlineData(1.1f)]
    public void ShouldThrow_WhenMainThresholdIsOutOfRange(float threshold)
    {
        var act = () => new DefenderPromptInjectionRule(new DefenderPromptInjectionOptions
        {
            MainThreshold = threshold,
            ModelPath = "/nonexistent/model.onnx",
            VocabPath = "/nonexistent/vocab.txt"
        });

        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Theory]
    [InlineData(-0.1f)]
    [InlineData(1.1f)]
    public void ShouldThrow_WhenAuxThresholdIsOutOfRange(float threshold)
    {
        var act = () => new DefenderPromptInjectionRule(new DefenderPromptInjectionOptions
        {
            AuxThreshold = threshold,
            ModelPath = "/nonexistent/model.onnx",
            VocabPath = "/nonexistent/vocab.txt"
        });

        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Theory]
    [InlineData(0f)]
    [InlineData(-1f)]
    public void ShouldThrow_WhenTemperatureIsNotPositive(float temperature)
    {
        var act = () => new DefenderPromptInjectionRule(new DefenderPromptInjectionOptions
        {
            TemperatureT = temperature,
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
        var rule = CreateRuleWithMockSession();

        var ctx = new GuardrailContext { Text = "", Phase = GuardrailPhase.Input };
        var result = await rule.EvaluateAsync(ctx);

        result.IsBlocked.Should().BeFalse();
    }

    [Fact]
    public async Task ShouldPass_WhenTextIsWhitespace()
    {
        var rule = CreateRuleWithMockSession();

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

        options.MainThreshold.Should().Be(0.5f);
        options.AuxThreshold.Should().Be(0.64f);
        options.TemperatureT.Should().Be(2.41f);
        options.MaxTokenLength.Should().Be(256);
        options.IncludeConfidence.Should().BeTrue();
        options.ModelPath.Should().BeNull();
        options.VocabPath.Should().BeNull();
    }

    // Shared session cache - multiple rules on the same model reuse one InferenceSession
    // (loads the real bundled model)

    [Fact]
    public void ShouldShareOneSession_AcrossRulesWithSameModel()
    {
        var before = DefenderModelSession.ActiveSessionCount;

        // two rules differing only in threshold (the cache key is model + maxLen + temperature,
        // not the decision thresholds), so they must share a single loaded session.
        var r1 = new DefenderPromptInjectionRule(new DefenderPromptInjectionOptions { MainThreshold = 0.5f });
        try
        {
            var afterOne = DefenderModelSession.ActiveSessionCount;
            afterOne.Should().Be(before + 1, "first rule loads the model");

            var r2 = new DefenderPromptInjectionRule(new DefenderPromptInjectionOptions { MainThreshold = 0.9f });
            try
            {
                DefenderModelSession.ActiveSessionCount.Should().Be(afterOne,
                    "a second rule on the same model must reuse the cached session, not load a copy");
            }
            finally
            {
                r2.Dispose();
            }

            DefenderModelSession.ActiveSessionCount.Should().Be(afterOne,
                "disposing one holder must not free the session while another still references it");
        }
        finally
        {
            r1.Dispose();
        }

        DefenderModelSession.ActiveSessionCount.Should().Be(before,
            "the session is freed once the last referencing rule is disposed");
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// <summary>
    /// Creates a rule with a null session via the internal constructor. Only safe for tests
    /// that do not call EvaluateAsync with non-empty text (those short-circuit before the session).
    /// </summary>
    private static DefenderPromptInjectionRule CreateRuleWithMockSession()
    {
        return new DefenderPromptInjectionRule(
            null!,
            new DefenderPromptInjectionOptions());
    }
}
