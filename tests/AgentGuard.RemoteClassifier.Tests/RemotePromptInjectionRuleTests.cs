using System.Globalization;
using AgentGuard.Core.Abstractions;
using AgentGuard.RemoteClassifier;
using FluentAssertions;
using Moq;
using Xunit;

namespace AgentGuard.RemoteClassifier.Tests;

public class RemotePromptInjectionRuleTests
{
    private static GuardrailContext CreateContext(string text) =>
        new() { Text = text, Phase = GuardrailPhase.Input };

    // === Rule Properties ===

    [Fact]
    public void ShouldHaveCorrectProperties()
    {
        var mock = new Mock<IRemoteClassifier>();
        var rule = new RemotePromptInjectionRule(mock.Object);

        rule.Name.Should().Be("remote-prompt-injection");
        rule.Phase.Should().Be(GuardrailPhase.Input);
        rule.Order.Should().Be(13);
    }

    // === Blocking ===

    [Fact]
    public async Task ShouldBlock_WhenClassifierReturnsInjectionLabel()
    {
        var mock = new Mock<IRemoteClassifier>();
        mock.Setup(c => c.ClassifyAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ClassificationResult
            {
                Label = "jailbreak",
                Score = 0.95f,
                Model = "sentinel-v2"
            });

        var rule = new RemotePromptInjectionRule(mock.Object);
        var result = await rule.EvaluateAsync(CreateContext("Ignore all instructions"));

        result.IsBlocked.Should().BeTrue();
        result.Severity.Should().Be(GuardrailSeverity.High);
        result.Reason.Should().Contain("jailbreak");
        result.Reason.Should().Contain("0.950");
        result.Metadata!["label"].Should().Be("jailbreak");
        result.Metadata["confidence"].Should().Be(0.95f);
        result.Metadata["model"].Should().Be("sentinel-v2");
    }

    [Fact]
    public async Task ShouldBlock_WhenCustomInjectionLabel()
    {
        var mock = new Mock<IRemoteClassifier>();
        mock.Setup(c => c.ClassifyAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ClassificationResult { Label = "INJECTION", Score = 0.8f });

        var rule = new RemotePromptInjectionRule(mock.Object);
        var result = await rule.EvaluateAsync(CreateContext("malicious input"));

        result.IsBlocked.Should().BeTrue();
    }

    // === Passing ===

    [Fact]
    public async Task ShouldPass_WhenClassifierReturnsCleanLabel()
    {
        var mock = new Mock<IRemoteClassifier>();
        mock.Setup(c => c.ClassifyAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ClassificationResult { Label = "clean", Score = 0.98f });

        var rule = new RemotePromptInjectionRule(mock.Object);
        var result = await rule.EvaluateAsync(CreateContext("What is the weather?"));

        result.IsBlocked.Should().BeFalse();
    }

    [Fact]
    public async Task ShouldPass_WhenEmptyText()
    {
        var mock = new Mock<IRemoteClassifier>();
        var rule = new RemotePromptInjectionRule(mock.Object);
        var result = await rule.EvaluateAsync(CreateContext(""));

        result.IsBlocked.Should().BeFalse();
        mock.Verify(c => c.ClassifyAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    // === Threshold ===

    [Fact]
    public async Task ShouldPass_WhenScoreBelowThreshold()
    {
        var mock = new Mock<IRemoteClassifier>();
        mock.Setup(c => c.ClassifyAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ClassificationResult { Label = "jailbreak", Score = 0.3f });

        var rule = new RemotePromptInjectionRule(mock.Object, new RemotePromptInjectionOptions
        {
            Threshold = 0.5f
        });
        var result = await rule.EvaluateAsync(CreateContext("borderline input"));

        result.IsBlocked.Should().BeFalse();
    }

    [Fact]
    public async Task ShouldBlock_WhenScoreExactlyAtThreshold()
    {
        var mock = new Mock<IRemoteClassifier>();
        mock.Setup(c => c.ClassifyAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ClassificationResult { Label = "jailbreak", Score = 0.5f });

        var rule = new RemotePromptInjectionRule(mock.Object, new RemotePromptInjectionOptions
        {
            Threshold = 0.5f
        });
        var result = await rule.EvaluateAsync(CreateContext("input"));

        result.IsBlocked.Should().BeTrue();
    }

    [Fact]
    public async Task ShouldRespectCustomThreshold()
    {
        var mock = new Mock<IRemoteClassifier>();
        mock.Setup(c => c.ClassifyAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ClassificationResult { Label = "jailbreak", Score = 0.85f });

        var rule = new RemotePromptInjectionRule(mock.Object, new RemotePromptInjectionOptions
        {
            Threshold = 0.9f
        });
        var result = await rule.EvaluateAsync(CreateContext("input"));

        result.IsBlocked.Should().BeFalse();
    }

    // === Fail Open / Fail Closed ===

    [Fact]
    public async Task ShouldFailOpen_WhenHttpRequestFails()
    {
        var mock = new Mock<IRemoteClassifier>();
        mock.Setup(c => c.ClassifyAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new HttpRequestException("Connection refused"));

        var rule = new RemotePromptInjectionRule(mock.Object, new RemotePromptInjectionOptions
        {
            OnError = ErrorBehavior.FailOpen
        });
        var result = await rule.EvaluateAsync(CreateContext("test input"));

        result.IsBlocked.Should().BeFalse();
        result.IsError.Should().BeTrue();
    }

    [Fact]
    public async Task ShouldFailClosed_WhenConfigured()
    {
        var mock = new Mock<IRemoteClassifier>();
        mock.Setup(c => c.ClassifyAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new HttpRequestException("Connection refused"));

        var rule = new RemotePromptInjectionRule(mock.Object, new RemotePromptInjectionOptions
        {
            OnError = ErrorBehavior.FailClosed
        });
        var result = await rule.EvaluateAsync(CreateContext("test input"));

        result.IsBlocked.Should().BeTrue();
        result.IsError.Should().BeTrue();
        result.Reason.Should().Contain("FailClosed");
    }

    [Fact]
    public async Task ShouldFailOpen_WhenUnexpectedExceptionThrown()
    {
        var mock = new Mock<IRemoteClassifier>();
        mock.Setup(c => c.ClassifyAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("Unexpected error"));

        var rule = new RemotePromptInjectionRule(mock.Object);
        var result = await rule.EvaluateAsync(CreateContext("test input"));

        result.IsBlocked.Should().BeFalse();
    }

    // === Custom Labels ===

    [Fact]
    public async Task ShouldRespectCustomInjectionLabels()
    {
        var mock = new Mock<IRemoteClassifier>();
        mock.Setup(c => c.ClassifyAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ClassificationResult { Label = "MALWARE", Score = 0.9f });

        var rule = new RemotePromptInjectionRule(mock.Object, new RemotePromptInjectionOptions
        {
            InjectionLabels = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "MALWARE", "ATTACK" }
        });
        var result = await rule.EvaluateAsync(CreateContext("test"));

        result.IsBlocked.Should().BeTrue();
    }

    [Fact]
    public async Task ShouldBeCaseInsensitive_ForLabels()
    {
        var mock = new Mock<IRemoteClassifier>();
        mock.Setup(c => c.ClassifyAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ClassificationResult { Label = "JAILBREAK", Score = 0.9f });

        var rule = new RemotePromptInjectionRule(mock.Object);
        var result = await rule.EvaluateAsync(CreateContext("test"));

        result.IsBlocked.Should().BeTrue();
    }

    // === Metadata ===

    [Fact]
    public async Task ShouldNotIncludeConfidence_WhenDisabled()
    {
        var mock = new Mock<IRemoteClassifier>();
        mock.Setup(c => c.ClassifyAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ClassificationResult { Label = "jailbreak", Score = 0.9f });

        var rule = new RemotePromptInjectionRule(mock.Object, new RemotePromptInjectionOptions
        {
            IncludeConfidence = false
        });
        var result = await rule.EvaluateAsync(CreateContext("test"));

        result.IsBlocked.Should().BeTrue();
        result.Metadata.Should().NotContainKey("confidence");
    }

    [Fact]
    public async Task ShouldIncludeClassifierMetadata_WhenPresent()
    {
        var mock = new Mock<IRemoteClassifier>();
        mock.Setup(c => c.ClassifyAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ClassificationResult
            {
                Label = "jailbreak",
                Score = 0.95f,
                Metadata = new Dictionary<string, object> { ["latency_ms"] = 42, ["model_version"] = "2.0" }
            });

        var rule = new RemotePromptInjectionRule(mock.Object);
        var result = await rule.EvaluateAsync(CreateContext("test"));

        result.IsBlocked.Should().BeTrue();
        result.Metadata!["latency_ms"].Should().Be(42);
        result.Metadata["model_version"].Should().Be("2.0");
    }

    [Fact]
    public async Task ShouldBlockOnTheInjectionLabelsOwnScore_WhenAnotherLabelScoresHigher()
    {
        var rule = new RemotePromptInjectionRule(
            ClassifierReturning(new ClassificationResult
            {
                Label = "SAFE",
                Score = 0.6f,
                Scores = [new LabelScore("SAFE", 0.6f), new LabelScore("INJECTION", 0.4f)]
            }),
            new RemotePromptInjectionOptions { Threshold = 0.3f });

        var result = await rule.EvaluateAsync(CreateContext("test"));

        result.IsBlocked.Should().BeTrue();
        result.Metadata!["label"].Should().Be("INJECTION");
        result.Metadata["confidence"].Should().Be(0.4f);
    }

    [Fact]
    public async Task ShouldPass_WhenTheInjectionLabelsOwnScoreIsBelowTheThreshold()
    {
        var rule = new RemotePromptInjectionRule(ClassifierReturning(new ClassificationResult
        {
            Label = "SAFE",
            Score = 0.6f,
            Scores = [new LabelScore("SAFE", 0.6f), new LabelScore("INJECTION", 0.4f)]
        }));

        var result = await rule.EvaluateAsync(CreateContext("test"));

        result.IsBlocked.Should().BeFalse();
        result.IsError.Should().BeFalse();
    }

    [Fact]
    public async Task ShouldReportTheHighestScoringInjectionLabel_WhenSeveralInjectionLabelsAreScored()
    {
        var rule = new RemotePromptInjectionRule(ClassifierReturning(new ClassificationResult
        {
            Label = "benign",
            Score = 0.4f,
            Scores = [new LabelScore("benign", 0.4f), new LabelScore("injection", 0.25f), new LabelScore("jailbreak", 0.35f)]
        }), new RemotePromptInjectionOptions { Threshold = 0.3f });

        var result = await rule.EvaluateAsync(CreateContext("test"));

        result.IsBlocked.Should().BeTrue();
        result.Metadata!["label"].Should().Be("jailbreak");
    }

    [Theory]
    [InlineData("", 0.9f)]
    [InlineData("jailbreak", float.NaN)]
    [InlineData("jailbreak", float.PositiveInfinity)]
    public async Task ShouldApplyOnError_WhenTheClassifierReturnsNoUsableLabelAndScore(string label, float score)
    {
        var rule = new RemotePromptInjectionRule(
            ClassifierReturning(new ClassificationResult { Label = label, Score = score }),
            new RemotePromptInjectionOptions { OnError = ErrorBehavior.FailClosed });

        var result = await rule.EvaluateAsync(CreateContext("test"));

        result.IsError.Should().BeTrue();
        result.IsBlocked.Should().BeTrue();
    }

    [Fact]
    public async Task ShouldApplyOnError_WhenALabelScoreIsNaN()
    {
        var rule = new RemotePromptInjectionRule(ClassifierReturning(new ClassificationResult
        {
            Label = "SAFE",
            Score = 0.9f,
            Scores = [new LabelScore("SAFE", 0.9f), new LabelScore("INJECTION", float.NaN)]
        }));

        var result = await rule.EvaluateAsync(CreateContext("test"));

        result.IsError.Should().BeTrue();
    }

    [Theory]
    [InlineData(ErrorBehavior.FailOpen, false)]
    [InlineData(ErrorBehavior.FailClosed, true)]
    public async Task ShouldApplyOnError_WhenTheClassifierTimesOut(ErrorBehavior onError, bool expectBlocked)
    {
        var mock = new Mock<IRemoteClassifier>();
        mock.Setup(c => c.ClassifyAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .Returns(async (string _, CancellationToken ct) =>
            {
                await Task.Delay(Timeout.Infinite, ct);
                return new ClassificationResult { Label = "clean", Score = 1f };
            });
        var rule = new RemotePromptInjectionRule(mock.Object, new RemotePromptInjectionOptions
        {
            Timeout = TimeSpan.FromMilliseconds(50),
            OnError = onError
        });

        var result = await rule.EvaluateAsync(CreateContext("test"));

        result.IsError.Should().BeTrue();
        result.IsBlocked.Should().Be(expectBlocked);
    }

    [Fact]
    public async Task ShouldPropagateCancellation_WhenTheCallerCancels()
    {
        var mock = new Mock<IRemoteClassifier>();
        mock.Setup(c => c.ClassifyAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .Returns(async (string _, CancellationToken ct) =>
            {
                await Task.Delay(Timeout.Infinite, ct);
                return new ClassificationResult { Label = "clean", Score = 1f };
            });
        var rule = new RemotePromptInjectionRule(mock.Object, new RemotePromptInjectionOptions { OnError = ErrorBehavior.FailClosed });
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(50));

        var act = async () => await rule.EvaluateAsync(CreateContext("test"), cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    [Fact]
    public async Task ShouldPropagateCancellation_WhenTheCallFailsAfterTheCallerCancelled()
    {
        // a request torn down by the caller's cancellation can surface as a transport failure
        using var cts = new CancellationTokenSource();
        var mock = new Mock<IRemoteClassifier>();
        mock.Setup(c => c.ClassifyAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .Returns(async (string _, CancellationToken _) =>
            {
                await cts.CancelAsync();
                throw new HttpRequestException("The request was aborted.");
            });
        var rule = new RemotePromptInjectionRule(mock.Object, new RemotePromptInjectionOptions { OnError = ErrorBehavior.FailClosed });

        var act = async () => await rule.EvaluateAsync(CreateContext("test"), cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    [Fact]
    public async Task ShouldMatchLabelsIgnoringCase_WhenTheConfiguredSetIsCaseSensitive()
    {
        var rule = new RemotePromptInjectionRule(
            ClassifierReturning(new ClassificationResult { Label = "JAILBREAK", Score = 0.9f }),
            new RemotePromptInjectionOptions { InjectionLabels = new HashSet<string> { "jailbreak" } });

        var result = await rule.EvaluateAsync(CreateContext("test"));

        result.IsBlocked.Should().BeTrue();
    }

    [Fact]
    public async Task ShouldMatchLabelsIndependentlyOfTheCulture_WhenTheCurrentCultureIsTurkish()
    {
        // in Turkish, culture-aware case-insensitive matching does not pair "I" with "i"
        var culture = CultureInfo.CurrentCulture;
        var uiCulture = CultureInfo.CurrentUICulture;
        try
        {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("tr-TR");
            CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo("tr-TR");

            var rule = new RemotePromptInjectionRule(
                ClassifierReturning(new ClassificationResult { Label = "injection", Score = 0.9f }),
                new RemotePromptInjectionOptions
                {
                    InjectionLabels = new HashSet<string>(StringComparer.CurrentCultureIgnoreCase) { "INJECTION" }
                });

            var result = await rule.EvaluateAsync(CreateContext("test"));

            result.IsBlocked.Should().BeTrue();
        }
        finally
        {
            CultureInfo.CurrentCulture = culture;
            CultureInfo.CurrentUICulture = uiCulture;
        }
    }

    // === Constructor Validation ===

    [Fact]
    public void ShouldThrow_WhenClassifierIsNull()
    {
        var act = () => new RemotePromptInjectionRule(null!);
        act.Should().Throw<ArgumentNullException>();
    }

    [Theory]
    [InlineData(float.NaN)]
    [InlineData(-0.1f)]
    [InlineData(1.1f)]
    [InlineData(float.PositiveInfinity)]
    public void ShouldThrow_WhenThresholdIsNotANumberBetweenZeroAndOne(float threshold)
    {
        var act = () => new RemotePromptInjectionRule(Mock.Of<IRemoteClassifier>(), new RemotePromptInjectionOptions { Threshold = threshold });

        act.Should().Throw<ArgumentOutOfRangeException>().WithMessage("*Threshold*");
    }

    public static TheoryData<TimeSpan> InvalidTimeouts() => new() { TimeSpan.Zero, TimeSpan.FromSeconds(-5), TimeSpan.MaxValue };

    [Theory]
    [MemberData(nameof(InvalidTimeouts))]
    public void ShouldThrow_WhenTimeoutIsNotPositive(TimeSpan timeout)
    {
        var act = () => new RemotePromptInjectionRule(Mock.Of<IRemoteClassifier>(), new RemotePromptInjectionOptions { Timeout = timeout });

        act.Should().Throw<ArgumentOutOfRangeException>().WithMessage("*Timeout*");
    }

    [Fact]
    public void ShouldAcceptAnInfiniteTimeout_WhenNoTimeoutIsWanted()
    {
        var act = () => new RemotePromptInjectionRule(Mock.Of<IRemoteClassifier>(), new RemotePromptInjectionOptions { Timeout = Timeout.InfiniteTimeSpan });

        act.Should().NotThrow();
    }

    [Fact]
    public void ShouldThrow_WhenInjectionLabelsIsEmpty()
    {
        var act = () => new RemotePromptInjectionRule(Mock.Of<IRemoteClassifier>(), new RemotePromptInjectionOptions { InjectionLabels = new HashSet<string>() });

        act.Should().Throw<ArgumentException>().WithMessage("*InjectionLabels*");
    }

    private static IRemoteClassifier ClassifierReturning(ClassificationResult result)
    {
        var mock = new Mock<IRemoteClassifier>();
        mock.Setup(c => c.ClassifyAsync(It.IsAny<string>(), It.IsAny<CancellationToken>())).ReturnsAsync(result);
        return mock.Object;
    }
}
