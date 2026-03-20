using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Rules.TopicBoundary;
using FluentAssertions;
using Moq;
using Xunit;

namespace AgentGuard.Core.Tests.Rules;

public class OutputTopicBoundaryRuleTests
{
    [Fact]
    public async Task ShouldHaveCorrectProperties()
    {
        var rule = new OutputTopicBoundaryRule(new OutputTopicBoundaryOptions { AllowedTopics = ["billing"] });
        rule.Name.Should().Be("output-topic-boundary");
        rule.Phase.Should().Be(GuardrailPhase.Output);
        rule.Order.Should().Be(60);
    }

    [Fact]
    public async Task ShouldPass_WhenNoAllowedTopics()
    {
        var rule = new OutputTopicBoundaryRule(new OutputTopicBoundaryOptions());
        var ctx = new GuardrailContext { Text = "Some response", Phase = GuardrailPhase.Output };
        var result = await rule.EvaluateAsync(ctx);
        result.IsBlocked.Should().BeFalse();
    }

    [Fact]
    public async Task ShouldPass_WhenTextIsEmpty()
    {
        var rule = new OutputTopicBoundaryRule(new OutputTopicBoundaryOptions { AllowedTopics = ["billing"] });
        var ctx = new GuardrailContext { Text = "", Phase = GuardrailPhase.Output };
        var result = await rule.EvaluateAsync(ctx);
        result.IsBlocked.Should().BeFalse();
    }

    [Fact]
    public async Task ShouldPass_WhenKeywordMatchesAllowedTopic()
    {
        var rule = new OutputTopicBoundaryRule(new OutputTopicBoundaryOptions
        {
            AllowedTopics = ["billing", "returns"]
        });
        var ctx = new GuardrailContext { Text = "Your billing statement is ready for review.", Phase = GuardrailPhase.Output };
        var result = await rule.EvaluateAsync(ctx);
        result.IsBlocked.Should().BeFalse();
    }

    [Fact]
    public async Task ShouldBlock_WhenKeywordDoesNotMatchAnyTopic()
    {
        var rule = new OutputTopicBoundaryRule(new OutputTopicBoundaryOptions
        {
            AllowedTopics = ["billing", "returns"]
        });
        var ctx = new GuardrailContext { Text = "Let me tell you about our investment strategy for next quarter.", Phase = GuardrailPhase.Output };
        var result = await rule.EvaluateAsync(ctx);
        result.IsBlocked.Should().BeTrue();
        result.Reason.Should().Contain("allowed topics");
    }

    [Fact]
    public async Task ShouldPass_WhenCustomKeywordMatches()
    {
        var rule = new OutputTopicBoundaryRule(new OutputTopicBoundaryOptions
        {
            AllowedTopics = ["support"],
            TopicKeywords = new Dictionary<string, IList<string>>
            {
                ["support"] = ["help", "assist", "ticket"]
            }
        });
        var ctx = new GuardrailContext { Text = "I can assist you with that right away.", Phase = GuardrailPhase.Output };
        var result = await rule.EvaluateAsync(ctx);
        result.IsBlocked.Should().BeFalse();
    }

    [Fact]
    public async Task ShouldPass_WhenEmbeddingSimilarityAboveThreshold()
    {
        var mockProvider = new Mock<ITopicSimilarityProvider>();
        mockProvider.Setup(p => p.ComputeSimilarityAsync("Your invoice is $49.99", "billing", It.IsAny<CancellationToken>()))
            .ReturnsAsync(0.85f);

        var rule = new OutputTopicBoundaryRule(
            new OutputTopicBoundaryOptions { AllowedTopics = ["billing"], SimilarityThreshold = 0.3f },
            mockProvider.Object);

        var ctx = new GuardrailContext { Text = "Your invoice is $49.99", Phase = GuardrailPhase.Output };
        var result = await rule.EvaluateAsync(ctx);
        result.IsBlocked.Should().BeFalse();
    }

    [Fact]
    public async Task ShouldBlock_WhenEmbeddingSimilarityBelowThreshold()
    {
        var mockProvider = new Mock<ITopicSimilarityProvider>();
        mockProvider.Setup(p => p.ComputeSimilarityAsync("Here's a recipe for chocolate cake", "billing", It.IsAny<CancellationToken>()))
            .ReturnsAsync(0.1f);

        var rule = new OutputTopicBoundaryRule(
            new OutputTopicBoundaryOptions { AllowedTopics = ["billing"], SimilarityThreshold = 0.3f },
            mockProvider.Object);

        var ctx = new GuardrailContext { Text = "Here's a recipe for chocolate cake", Phase = GuardrailPhase.Output };
        var result = await rule.EvaluateAsync(ctx);
        result.IsBlocked.Should().BeTrue();
        result.Reason.Should().Contain("billing");
        result.Metadata.Should().ContainKey("best_match_topic");
        result.Metadata!["best_match_topic"].Should().Be("billing");
        result.Metadata.Should().ContainKey("best_match_similarity");
    }

    [Fact]
    public async Task ShouldSelectBestTopic_WhenMultipleTopicsAvailable()
    {
        var mockProvider = new Mock<ITopicSimilarityProvider>();
        mockProvider.Setup(p => p.ComputeSimilarityAsync("Your refund has been processed", "billing", It.IsAny<CancellationToken>()))
            .ReturnsAsync(0.5f);
        mockProvider.Setup(p => p.ComputeSimilarityAsync("Your refund has been processed", "returns", It.IsAny<CancellationToken>()))
            .ReturnsAsync(0.9f);

        var rule = new OutputTopicBoundaryRule(
            new OutputTopicBoundaryOptions { AllowedTopics = ["billing", "returns"], SimilarityThreshold = 0.3f },
            mockProvider.Object);

        var ctx = new GuardrailContext { Text = "Your refund has been processed", Phase = GuardrailPhase.Output };
        var result = await rule.EvaluateAsync(ctx);
        result.IsBlocked.Should().BeFalse();
    }

    [Fact]
    public async Task ShouldWarn_WhenActionIsWarnAndTopicDrifts()
    {
        var mockProvider = new Mock<ITopicSimilarityProvider>();
        mockProvider.Setup(p => p.ComputeSimilarityAsync("Disney movies are great", "billing", It.IsAny<CancellationToken>()))
            .ReturnsAsync(0.05f);

        var rule = new OutputTopicBoundaryRule(
            new OutputTopicBoundaryOptions
            {
                AllowedTopics = ["billing"],
                SimilarityThreshold = 0.3f,
                Action = OutputTopicAction.Warn
            },
            mockProvider.Object);

        var ctx = new GuardrailContext { Text = "Disney movies are great", Phase = GuardrailPhase.Output };
        var result = await rule.EvaluateAsync(ctx);
        result.IsBlocked.Should().BeFalse();
        result.Reason.Should().Contain("billing");
        result.Metadata.Should().ContainKey("best_match_topic");
        result.Metadata.Should().ContainKey("allowed_topics");
    }

    [Fact]
    public async Task ShouldWarn_WhenActionIsWarnAndKeywordMismatch()
    {
        var rule = new OutputTopicBoundaryRule(new OutputTopicBoundaryOptions
        {
            AllowedTopics = ["billing"],
            Action = OutputTopicAction.Warn
        });

        var ctx = new GuardrailContext { Text = "Let me tell you about quantum physics.", Phase = GuardrailPhase.Output };
        var result = await rule.EvaluateAsync(ctx);
        result.IsBlocked.Should().BeFalse();
        result.Reason.Should().Contain("allowed topics");
        result.Metadata.Should().ContainKey("allowed_topics");
    }

    [Fact]
    public async Task ShouldPass_WhenNoProviderAndKeywordFallbackDisabled()
    {
        var rule = new OutputTopicBoundaryRule(new OutputTopicBoundaryOptions
        {
            AllowedTopics = ["billing"],
            AllowKeywordFallback = false
        });

        var ctx = new GuardrailContext { Text = "Totally off topic response", Phase = GuardrailPhase.Output };
        var result = await rule.EvaluateAsync(ctx);
        result.IsBlocked.Should().BeFalse();
    }

    [Fact]
    public async Task ShouldIncludeAllowedTopicsInMetadata_WhenBlocked()
    {
        var rule = new OutputTopicBoundaryRule(new OutputTopicBoundaryOptions
        {
            AllowedTopics = ["billing", "returns", "shipping"]
        });

        var ctx = new GuardrailContext { Text = "Let me recommend some great recipes.", Phase = GuardrailPhase.Output };
        var result = await rule.EvaluateAsync(ctx);
        result.IsBlocked.Should().BeTrue();
        result.Metadata!["allowed_topics"].Should().Be("billing, returns, shipping");
    }
}
