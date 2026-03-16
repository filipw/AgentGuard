using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Rules.ContentSafety;
using FluentAssertions;
using Moq;
using Xunit;

namespace AgentGuard.Core.Tests.Rules;

public class ContentSafetyRuleTests
{
    private static GuardrailContext Ctx(string text) => new() { Text = text, Phase = GuardrailPhase.Input };

    [Fact]
    public async Task ShouldPass_WhenNoClassifierConfigured()
    {
        var rule = new ContentSafetyRule();
        var result = await rule.EvaluateAsync(Ctx("anything"));
        result.IsBlocked.Should().BeFalse();
    }

    [Fact]
    public async Task ShouldPass_WhenClassifierReturnsSafe()
    {
        var mock = new Mock<IContentSafetyClassifier>();
        mock.Setup(c => c.AnalyzeAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new List<ContentSafetyAnalysis>
            {
                new() { Category = ContentSafetyCategory.Violence, Severity = ContentSafetySeverity.Safe }
            });

        var rule = new ContentSafetyRule(classifier: mock.Object);
        var result = await rule.EvaluateAsync(Ctx("peaceful text"));
        result.IsBlocked.Should().BeFalse();
    }

    [Fact]
    public async Task ShouldBlock_WhenSeverityExceedsThreshold()
    {
        var mock = new Mock<IContentSafetyClassifier>();
        mock.Setup(c => c.AnalyzeAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new List<ContentSafetyAnalysis>
            {
                new() { Category = ContentSafetyCategory.Hate, Severity = ContentSafetySeverity.High }
            });

        var rule = new ContentSafetyRule(new ContentSafetyOptions { MaxAllowedSeverity = ContentSafetySeverity.Low }, mock.Object);
        var result = await rule.EvaluateAsync(Ctx("hateful text"));
        result.IsBlocked.Should().BeTrue();
        result.Reason.Should().Contain("Hate");
        result.Severity.Should().Be(GuardrailSeverity.Critical);
    }

    [Fact]
    public async Task ShouldPass_WhenSeverityWithinThreshold()
    {
        var mock = new Mock<IContentSafetyClassifier>();
        mock.Setup(c => c.AnalyzeAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new List<ContentSafetyAnalysis>
            {
                new() { Category = ContentSafetyCategory.Violence, Severity = ContentSafetySeverity.Low }
            });

        var rule = new ContentSafetyRule(new ContentSafetyOptions { MaxAllowedSeverity = ContentSafetySeverity.Medium }, mock.Object);
        var result = await rule.EvaluateAsync(Ctx("mild text"));
        result.IsBlocked.Should().BeFalse();
    }

    [Fact]
    public async Task ShouldRespectCategoryFilter()
    {
        var mock = new Mock<IContentSafetyClassifier>();
        mock.Setup(c => c.AnalyzeAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new List<ContentSafetyAnalysis>
            {
                new() { Category = ContentSafetyCategory.Violence, Severity = ContentSafetySeverity.High }
            });

        // Only checking Hate category, not Violence
        var rule = new ContentSafetyRule(new ContentSafetyOptions
        {
            Categories = ContentSafetyCategory.Hate,
            MaxAllowedSeverity = ContentSafetySeverity.Low
        }, mock.Object);

        var result = await rule.EvaluateAsync(Ctx("violent text"));
        result.IsBlocked.Should().BeFalse();
    }

    [Fact]
    public async Task ShouldMapMediumSeverityCorrectly()
    {
        var mock = new Mock<IContentSafetyClassifier>();
        mock.Setup(c => c.AnalyzeAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new List<ContentSafetyAnalysis>
            {
                new() { Category = ContentSafetyCategory.SelfHarm, Severity = ContentSafetySeverity.Medium }
            });

        var rule = new ContentSafetyRule(new ContentSafetyOptions { MaxAllowedSeverity = ContentSafetySeverity.Low }, mock.Object);
        var result = await rule.EvaluateAsync(Ctx("concerning text"));
        result.IsBlocked.Should().BeTrue();
        result.Severity.Should().Be(GuardrailSeverity.High);
    }

    [Fact]
    public async Task ShouldPass_WhenClassifierReturnsEmpty()
    {
        var mock = new Mock<IContentSafetyClassifier>();
        mock.Setup(c => c.AnalyzeAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new List<ContentSafetyAnalysis>());

        var rule = new ContentSafetyRule(classifier: mock.Object);
        var result = await rule.EvaluateAsync(Ctx("clean text"));
        result.IsBlocked.Should().BeFalse();
    }

    [Fact]
    public void ShouldHaveCorrectPhaseAndOrder()
    {
        var rule = new ContentSafetyRule();
        rule.Phase.Should().Be(GuardrailPhase.Both);
        rule.Order.Should().Be(50);
        rule.Name.Should().Be("content-safety");
    }
}
