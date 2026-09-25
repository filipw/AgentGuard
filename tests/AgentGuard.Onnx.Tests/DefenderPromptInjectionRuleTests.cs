using AgentGuard.Core.Abstractions;
using Kyoto;
using AgentGuard.Onnx;
using FluentAssertions;
using Xunit;

namespace AgentGuard.Onnx.Tests;

/// <summary>
/// Unit tests for <see cref="DefenderPromptInjectionRule"/> and the internal
/// <see cref="DefenderModelSession"/> helpers. These do not load the real model -
/// see <c>DefenderPromptInjectionE2ETests</c> for tests against the bundled model.
/// </summary>
[Collection(DefenderModelCollection.Name)]
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

        options.MainThreshold.Should().Be(0.75f);
        options.AuxThreshold.Should().Be(0.64f);
        options.TemperatureT.Should().Be(2.41f);
        options.MaxTokenLength.Should().Be(256);
        options.WindowSize.Should().Be(64);
        options.WindowOverlap.Should().Be(32);
        options.MaxWindows.Should().Be(512);
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

    // windowing: input longer than one window is classified window by window (fake classifier that
    // flags any window containing INJECT, and one token per word)

    [Fact]
    public async Task ShouldClassifyWholeTextInOneCall_WhenTextFitsInOneWindow()
    {
        var text = WindowingTestHelpers.WordsWithMarker(64, 10, "INJECT");
        var calls = new List<string>();
        var rule = CreateWindowedRule(new DefenderPromptInjectionOptions(), calls);

        var result = await rule.EvaluateAsync(new GuardrailContext { Text = text, Phase = GuardrailPhase.Input });

        calls.Should().Equal([text], "text that fits in one window must be classified exactly as before, in one call");
        result.IsBlocked.Should().BeTrue();
        result.Reason.Should().Be($"Defender classifier detected potential prompt injection (main: {0.97f:P1}, aux: {0.1f:P1}).");
        result.Metadata.Should().NotContainKey("windowCount");
        result.Metadata.Should().NotContainKey("windowIndex");
    }

    [Fact]
    public async Task ShouldBlock_WhenInjectionIsBeyondTheFirstWindow()
    {
        var text = WindowingTestHelpers.WordsWithMarker(1000, 900, "INJECT");
        var rule = CreateWindowedRule(new DefenderPromptInjectionOptions());

        var result = await rule.EvaluateAsync(new GuardrailContext { Text = text, Phase = GuardrailPhase.Input });

        result.IsBlocked.Should().BeTrue("text past the model's input length must still be classified");
        result.Severity.Should().Be(GuardrailSeverity.Critical);
        result.Reason.Should().Contain("window");
        result.Metadata!["mainScore"].Should().Be(0.97f);
        ((int)result.Metadata["windowCount"]).Should().BeGreaterThan(1);
        var start = (int)result.Metadata["windowStart"];
        var length = (int)result.Metadata["windowLength"];
        text.Substring(start, length).Should().Contain("INJECT", "the reported window is the one that blocked");
    }

    [Fact]
    public async Task ShouldClassifyEveryWord_WhenTextIsSplitIntoWindows()
    {
        var text = WindowingTestHelpers.Words(1000);
        var calls = new List<string>();
        var rule = CreateWindowedRule(new DefenderPromptInjectionOptions(), calls);

        var result = await rule.EvaluateAsync(new GuardrailContext { Text = text, Phase = GuardrailPhase.Input });

        result.IsBlocked.Should().BeFalse();
        calls.Should().HaveCountGreaterThan(1);
        calls.Should().OnlyContain(window => WindowingTestHelpers.CountWords(window) <= 64);
        calls.SelectMany(window => window.Split(' ')).Distinct().Should().HaveCount(1000, "no word may go unclassified");
    }

    [Fact]
    public async Task ShouldReportHighestScoringBlockingWindow_WhenSeveralWindowsBlock()
    {
        var words = WindowingTestHelpers.Words(1000).Split(' ');
        words[100] = "WEAK";
        words[800] = "STRONG";
        var rule = new DefenderPromptInjectionRule(
            text => text.Contains("STRONG") ? new DefenderScore(0.95f, 0.1f)
                : text.Contains("WEAK") ? new DefenderScore(0.8f, 0.1f)
                : new DefenderScore(0.05f, 0.3f),
            WindowingTestHelpers.CountWords,
            new DefenderPromptInjectionOptions());

        var result = await rule.EvaluateAsync(new GuardrailContext { Text = string.Join(' ', words), Phase = GuardrailPhase.Input });

        result.IsBlocked.Should().BeTrue();
        result.Metadata!["mainScore"].Should().Be(0.95f);
    }

    [Fact]
    public async Task ShouldReportBlockingWindow_WhenAHigherScoringWindowIsVetoed()
    {
        var words = WindowingTestHelpers.Words(1000).Split(' ');
        words[100] = "VETOED";
        words[800] = "INJECT";
        var rule = new DefenderPromptInjectionRule(
            text => text.Contains("VETOED") ? new DefenderScore(0.99f, 0.9f)
                : text.Contains("INJECT") ? new DefenderScore(0.8f, 0.1f)
                : new DefenderScore(0.05f, 0.3f),
            WindowingTestHelpers.CountWords,
            new DefenderPromptInjectionOptions());

        var result = await rule.EvaluateAsync(new GuardrailContext { Text = string.Join(' ', words), Phase = GuardrailPhase.Input });

        result.IsBlocked.Should().BeTrue();
        result.Metadata!["mainScore"].Should().Be(0.8f, "a window vetoed by the aux head does not block and is not reported");
    }

    [Fact]
    public async Task ShouldBlockAsTooLong_WhenInputNeedsMoreThanMaxWindows()
    {
        var rule = new DefenderPromptInjectionRule(
            WindowingTestHelpers.NotCalled<DefenderScore>,
            WindowingTestHelpers.CountWords,
            new DefenderPromptInjectionOptions { MaxWindows = 3 });

        var result = await rule.EvaluateAsync(new GuardrailContext { Text = WindowingTestHelpers.Words(1000), Phase = GuardrailPhase.Input });

        result.IsBlocked.Should().BeTrue("input that cannot be scanned completely must not pass");
        result.Severity.Should().Be(GuardrailSeverity.Medium);
        result.Reason.Should().Contain("MaxWindows");
        result.Metadata!["inputTooLong"].Should().Be(true);
        result.Metadata["maxWindows"].Should().Be(3);
    }

    [Fact]
    public async Task ShouldScanEveryWindow_WhenMaxWindowsIsZero()
    {
        var calls = new List<string>();
        var rule = CreateWindowedRule(new DefenderPromptInjectionOptions { MaxWindows = 0 }, calls);

        var result = await rule.EvaluateAsync(new GuardrailContext { Text = WindowingTestHelpers.Words(40_000), Phase = GuardrailPhase.Input });

        result.IsBlocked.Should().BeFalse();
        calls.Should().HaveCountGreaterThan(512, "no limit applies when MaxWindows is 0");
    }

    [Fact]
    public async Task ShouldThrowOperationCanceled_WhenCancelledDuringWindowedClassification()
    {
        var rule = CreateWindowedRule(new DefenderPromptInjectionOptions());
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        var act = async () => await rule.EvaluateAsync(
            new GuardrailContext { Text = WindowingTestHelpers.Words(1000), Phase = GuardrailPhase.Input }, cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    [Fact]
    public async Task ShouldCapWindowSize_WhenWindowSizeExceedsWhatMaxTokenLengthAllows()
    {
        var calls = new List<string>();
        var rule = CreateWindowedRule(
            new DefenderPromptInjectionOptions { MaxTokenLength = 18, WindowSize = 64, WindowOverlap = 8 }, calls);

        await rule.EvaluateAsync(new GuardrailContext { Text = WindowingTestHelpers.Words(200), Phase = GuardrailPhase.Input });

        calls.Should().OnlyContain(window => WindowingTestHelpers.CountWords(window) <= 16,
            "a window must fit in MaxTokenLength minus [CLS] and [SEP]");
    }

    [Theory]
    [InlineData(0, 0)]
    [InlineData(-1, 0)]
    [InlineData(32, 32)]
    [InlineData(64, 100)]
    [InlineData(64, -1)]
    public void ShouldThrow_WhenWindowSettingsAreInvalid(int windowSize, int windowOverlap)
    {
        var act = () => new DefenderPromptInjectionRule(new DefenderPromptInjectionOptions
        {
            WindowSize = windowSize,
            WindowOverlap = windowOverlap,
            ModelPath = "/nonexistent/model.onnx",
            VocabPath = "/nonexistent/vocab.txt"
        });

        act.Should().Throw<ArgumentOutOfRangeException>().WithMessage("*Window*");
    }

    [Fact]
    public void ShouldThrow_WhenMaxWindowsIsNegative()
    {
        var act = () => new DefenderPromptInjectionRule(new DefenderPromptInjectionOptions
        {
            MaxWindows = -1,
            ModelPath = "/nonexistent/model.onnx",
            VocabPath = "/nonexistent/vocab.txt"
        });

        act.Should().Throw<ArgumentOutOfRangeException>().WithMessage("*MaxWindows*");
    }

    [Fact]
    public void ShouldThrow_WhenWindowOverlapDoesNotFitTheCappedWindow()
    {
        // a MaxTokenLength of 34 leaves 32 content tokens, so the default 32-token overlap does not fit
        var act = () => new DefenderPromptInjectionRule(
            WindowingTestHelpers.NotCalled<DefenderScore>,
            WindowingTestHelpers.CountWords,
            new DefenderPromptInjectionOptions { MaxTokenLength = 34 });

        act.Should().Throw<ArgumentOutOfRangeException>().WithMessage("*WindowOverlap*");
    }

    /// <summary>
    /// A rule over a fake classifier that flags any window containing <c>INJECT</c> (main 0.97,
    /// aux 0.10) and records every text it is asked to classify.
    /// </summary>
    private static DefenderPromptInjectionRule CreateWindowedRule(DefenderPromptInjectionOptions options, List<string>? calls = null)
    {
        return new DefenderPromptInjectionRule(
            text =>
            {
                calls?.Add(text);
                return text.Contains("INJECT") ? new DefenderScore(0.97f, 0.1f) : new DefenderScore(0.05f, 0.3f);
            },
            WindowingTestHelpers.CountWords,
            options);
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// <summary>
    /// Creates a rule without a model via the internal constructor. Only safe for tests that do not
    /// call EvaluateAsync with non-empty text (those short-circuit before the classifier).
    /// </summary>
    private static DefenderPromptInjectionRule CreateRuleWithMockSession()
    {
        return new DefenderPromptInjectionRule(
            WindowingTestHelpers.NotCalled<DefenderScore>,
            WindowingTestHelpers.CountWords,
            new DefenderPromptInjectionOptions());
    }
}
