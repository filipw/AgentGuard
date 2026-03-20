using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Builders;
using AgentGuard.Core.Guardrails;
using AgentGuard.Core.Rules.TopicBoundary;
using AgentGuard.Local.Classifiers;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace AgentGuard.E2E.Tests;

/// <summary>
/// End-to-end tests for <see cref="OutputTopicBoundaryRule"/> using a real embedding model.
/// Validates that agent responses are correctly evaluated against allowed output topics.
/// </summary>
public sealed class OutputTopicBoundaryE2ETests : IClassFixture<EmbeddingTestFixture>
{
    private readonly EmbeddingTestFixture _fixture;

    public OutputTopicBoundaryE2ETests(EmbeddingTestFixture fixture)
    {
        _fixture = fixture;
    }

    [EmbeddingFact]
    public async Task ShouldPass_WhenResponseIsOnTopic()
    {
        var provider = new EmbeddingSimilarityProvider(_fixture.EmbeddingGenerator!);
        var rule = new OutputTopicBoundaryRule(
            new OutputTopicBoundaryOptions
            {
                AllowedTopics = ["billing", "invoices", "payments"],
                SimilarityThreshold = 0.3f
            },
            provider);

        var ctx = new GuardrailContext
        {
            Text = "Your invoice for March was $49.99. The payment was processed on March 15th.",
            Phase = GuardrailPhase.Output
        };

        var result = await rule.EvaluateAsync(ctx);
        result.IsBlocked.Should().BeFalse("response about invoices should match billing topics");
    }

    [EmbeddingFact]
    public async Task ShouldBlock_WhenResponseDriftsOffTopic()
    {
        var provider = new EmbeddingSimilarityProvider(_fixture.EmbeddingGenerator!);
        var rule = new OutputTopicBoundaryRule(
            new OutputTopicBoundaryOptions
            {
                AllowedTopics = ["billing", "invoices", "payments"],
                SimilarityThreshold = 0.5f
            },
            provider);

        var ctx = new GuardrailContext
        {
            Text = "Here is a delicious recipe for homemade pasta with fresh tomato sauce and basil.",
            Phase = GuardrailPhase.Output
        };

        var result = await rule.EvaluateAsync(ctx);
        result.IsBlocked.Should().BeTrue("a recipe response should not match billing topics");
        result.Metadata.Should().ContainKey("best_match_topic");
    }

    [EmbeddingFact]
    public async Task ShouldWorkInPipeline_WhenCombinedWithOtherRules()
    {
        var provider = new EmbeddingSimilarityProvider(_fixture.EmbeddingGenerator!);

        var policy = new GuardrailPolicyBuilder("output-topic-e2e")
            .EnforceOutputTopicBoundary(provider, 0.5f, "customer support", "billing", "returns")
            .Build();

        var pipeline = new GuardrailPipeline(policy, NullLogger<GuardrailPipeline>.Instance);

        // On-topic response
        var onTopicCtx = new GuardrailContext
        {
            Text = "I've processed your return request. The refund of $29.99 will appear on your statement within 5-7 business days.",
            Phase = GuardrailPhase.Output
        };
        var onTopicResult = await pipeline.RunAsync(onTopicCtx);
        onTopicResult.IsBlocked.Should().BeFalse("return/refund response should match customer support topics");

        // Off-topic response
        var offTopicCtx = new GuardrailContext
        {
            Text = "The quantum mechanical properties of semiconductor materials make them ideal for photovoltaic energy conversion.",
            Phase = GuardrailPhase.Output
        };
        var offTopicResult = await pipeline.RunAsync(offTopicCtx);
        offTopicResult.IsBlocked.Should().BeTrue("physics response should not match customer support topics");
    }
}
