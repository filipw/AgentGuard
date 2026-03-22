using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Rules.TopicBoundary;
using AgentGuard.Local.Classifiers;
using FluentAssertions;
using Xunit;

namespace AgentGuard.E2E.Tests;

/// <summary>
/// End-to-end tests for <see cref="EmbeddingSimilarityProvider"/> using a real embedding model.
/// Validates that cosine similarity of real embeddings correctly differentiates
/// on-topic vs off-topic inputs for topic boundary enforcement.
/// </summary>
public sealed class EmbeddingSimilarityE2ETests : IClassFixture<EmbeddingTestFixture>
{
    private readonly EmbeddingTestFixture _fixture;

    public EmbeddingSimilarityE2ETests(EmbeddingTestFixture fixture)
    {
        _fixture = fixture;
    }

    [EmbeddingFact]
    public async Task ShouldReturnHighSimilarity_WhenInputMatchesTopic()
    {
        var provider = new EmbeddingSimilarityProvider(_fixture.EmbeddingGenerator!);

        var similarity = await provider.ComputeSimilarityAsync(
            "I need help with my monthly invoice", "billing");

        similarity.Should().BeGreaterThan(0.3f, "billing-related input should match 'billing' topic");
    }

    [EmbeddingFact]
    public async Task ShouldReturnLowerSimilarity_WhenInputIsOffTopic()
    {
        var provider = new EmbeddingSimilarityProvider(_fixture.EmbeddingGenerator!);

        var onTopicScore = await provider.ComputeSimilarityAsync(
            "I need help with my monthly invoice", "billing");
        var offTopicScore = await provider.ComputeSimilarityAsync(
            "What is the best recipe for chocolate cake?", "billing");

        offTopicScore.Should().BeLessThan(onTopicScore,
            "off-topic input should have lower similarity than on-topic input");
    }

    [EmbeddingFact]
    public async Task ShouldDistinguishTopics_WhenMultipleTopicsAreAvailable()
    {
        var provider = new EmbeddingSimilarityProvider(_fixture.EmbeddingGenerator!);

        var billingScore = await provider.ComputeSimilarityAsync(
            "Can you explain the charges on my credit card statement?", "billing and payments");
        var supportScore = await provider.ComputeSimilarityAsync(
            "Can you explain the charges on my credit card statement?", "technical support and troubleshooting");

        billingScore.Should().BeGreaterThan(supportScore,
            "billing-related input should score higher for 'billing' than 'technical support'");
    }

    [EmbeddingFact]
    public async Task ShouldWorkWithTopicBoundaryRule_WhenOnTopic()
    {
        var provider = new EmbeddingSimilarityProvider(_fixture.EmbeddingGenerator!);
        var rule = new TopicBoundaryRule(
            new TopicBoundaryOptions
            {
                AllowedTopics = ["billing", "returns", "customer support"],
                SimilarityThreshold = 0.2f
            },
            provider);

        var context = new GuardrailContext
        {
            Text = "I want to return a defective product I purchased last week.",
            Phase = GuardrailPhase.Input
        };
        var result = await rule.EvaluateAsync(context);

        result.IsBlocked.Should().BeFalse(
            "returns-related input should pass topic boundary with 'returns' as allowed topic");
    }

    [EmbeddingFact]
    public async Task ShouldWorkWithTopicBoundaryRule_WhenOffTopic()
    {
        var provider = new EmbeddingSimilarityProvider(_fixture.EmbeddingGenerator!);
        var rule = new TopicBoundaryRule(
            new TopicBoundaryOptions
            {
                AllowedTopics = ["billing", "returns"],
                SimilarityThreshold = 0.5f
            },
            provider);

        var context = new GuardrailContext
        {
            Text = "Tell me about the history of the Roman Empire.",
            Phase = GuardrailPhase.Input
        };
        var result = await rule.EvaluateAsync(context);

        result.IsBlocked.Should().BeTrue(
            "history question should be blocked when only billing/returns are allowed");
    }

    [EmbeddingFact]
    public async Task ShouldCacheTopicEmbeddings_WhenCalledMultipleTimes()
    {
        var provider = new EmbeddingSimilarityProvider(_fixture.EmbeddingGenerator!);

        // First call - computes and caches the topic embedding
        var score1 = await provider.ComputeSimilarityAsync("pay my bill", "billing");

        // Second call with same topic - should use cached embedding
        var score2 = await provider.ComputeSimilarityAsync("invoice payment", "billing");

        // Both should return valid similarity scores (caching doesn't break results)
        score1.Should().BeGreaterOrEqualTo(0f).And.BeLessOrEqualTo(1f);
        score2.Should().BeGreaterOrEqualTo(0f).And.BeLessOrEqualTo(1f);
    }

    [EmbeddingFact]
    public async Task ShouldHandleDescriptiveTopics_WhenUsingFullPhrases()
    {
        var provider = new EmbeddingSimilarityProvider(_fixture.EmbeddingGenerator!);

        // Use descriptive topic phrases instead of single keywords
        var similarity = await provider.ComputeSimilarityAsync(
            "My server keeps crashing when I deploy the new version",
            "technical support for software deployment and server infrastructure");

        similarity.Should().BeGreaterThan(0.3f,
            "descriptive topic phrases should provide good semantic matching");
    }
}
