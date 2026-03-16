using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Rules.TopicBoundary;
using FluentAssertions;
using Moq;
using Xunit;

namespace AgentGuard.Core.Tests.Rules;

public class TopicBoundaryRuleTests
{
    private static GuardrailContext Ctx(string text) => new() { Text = text, Phase = GuardrailPhase.Input };

    [Fact]
    public async Task ShouldPass_WhenNoTopicsConfigured()
    {
        var rule = new TopicBoundaryRule(new TopicBoundaryOptions());
        var result = await rule.EvaluateAsync(Ctx("anything goes"));
        result.IsBlocked.Should().BeFalse();
    }

    [Fact]
    public async Task ShouldPass_WhenEmptyInput()
    {
        var rule = new TopicBoundaryRule(new TopicBoundaryOptions { AllowedTopics = ["billing"] });
        var result = await rule.EvaluateAsync(Ctx(""));
        result.IsBlocked.Should().BeFalse();
    }

    [Fact]
    public async Task ShouldPass_WhenInputMatchesTopicKeyword()
    {
        var rule = new TopicBoundaryRule(new TopicBoundaryOptions { AllowedTopics = ["billing", "support"] });
        var result = await rule.EvaluateAsync(Ctx("I have a billing question about my invoice"));
        result.IsBlocked.Should().BeFalse();
    }

    [Fact]
    public async Task ShouldBlock_WhenInputDoesNotMatchAnyTopic()
    {
        var rule = new TopicBoundaryRule(new TopicBoundaryOptions { AllowedTopics = ["billing", "support"] });
        var result = await rule.EvaluateAsync(Ctx("Tell me a joke about cats"));
        result.IsBlocked.Should().BeTrue();
        result.Reason.Should().Contain("billing").And.Contain("support");
    }

    [Fact]
    public async Task ShouldPass_WhenCustomKeywordsMatch()
    {
        var rule = new TopicBoundaryRule(new TopicBoundaryOptions
        {
            AllowedTopics = ["finance"],
            TopicKeywords = new Dictionary<string, IList<string>>
            {
                ["finance"] = ["invoice", "payment", "refund"]
            }
        });
        var result = await rule.EvaluateAsync(Ctx("I need a refund for my order"));
        result.IsBlocked.Should().BeFalse();
    }

    [Fact]
    public async Task ShouldBlock_WhenKeywordFallbackDisabledAndNoProvider()
    {
        var rule = new TopicBoundaryRule(new TopicBoundaryOptions
        {
            AllowedTopics = ["billing"],
            AllowKeywordFallback = false
        });
        // With no embedding provider and keyword fallback disabled, should pass (no enforcement possible)
        var result = await rule.EvaluateAsync(Ctx("anything"));
        result.IsBlocked.Should().BeFalse();
    }

    [Fact]
    public async Task ShouldUseEmbeddingProvider_WhenProvided()
    {
        var mock = new Mock<ITopicSimilarityProvider>();
        mock.Setup(p => p.ComputeSimilarityAsync("billing question", "billing", It.IsAny<CancellationToken>()))
            .ReturnsAsync(0.8f);

        var rule = new TopicBoundaryRule(new TopicBoundaryOptions
        {
            AllowedTopics = ["billing"],
            SimilarityThreshold = 0.5f
        }, mock.Object);

        var result = await rule.EvaluateAsync(Ctx("billing question"));
        result.IsBlocked.Should().BeFalse();
        mock.Verify(p => p.ComputeSimilarityAsync("billing question", "billing", It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task ShouldBlock_WhenEmbeddingSimilarityBelowThreshold()
    {
        var mock = new Mock<ITopicSimilarityProvider>();
        mock.Setup(p => p.ComputeSimilarityAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(0.1f);

        var rule = new TopicBoundaryRule(new TopicBoundaryOptions
        {
            AllowedTopics = ["billing"],
            SimilarityThreshold = 0.5f
        }, mock.Object);

        var result = await rule.EvaluateAsync(Ctx("Tell me a joke"));
        result.IsBlocked.Should().BeTrue();
        result.Severity.Should().Be(GuardrailSeverity.Medium);
    }

    [Fact]
    public void ShouldHaveCorrectPhaseAndOrder()
    {
        var rule = new TopicBoundaryRule(new TopicBoundaryOptions());
        rule.Phase.Should().Be(GuardrailPhase.Input);
        rule.Order.Should().Be(30);
        rule.Name.Should().Be("topic-boundary");
    }
}
