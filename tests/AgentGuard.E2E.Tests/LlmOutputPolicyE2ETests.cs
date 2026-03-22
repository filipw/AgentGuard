using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Rules.LLM;
using FluentAssertions;
using Xunit;

namespace AgentGuard.E2E.Tests;

public sealed class LlmOutputPolicyE2ETests : IClassFixture<LlmTestFixture>
{
    private readonly LlmTestFixture _fixture;

    public LlmOutputPolicyE2ETests(LlmTestFixture fixture) => _fixture = fixture;

    [LlmFact]
    public async Task ShouldPass_WhenResponseCompliesWithPolicy()
    {
        var rule = new LlmOutputPolicyRule(_fixture.ChatClient!,
            new LlmOutputPolicyOptions { PolicyDescription = "Never recommend competitor products or services." },
            _fixture.ChatOptions);

        var ctx = new GuardrailContext
        {
            Text = "Our product offers real-time analytics, custom dashboards, and API integrations to meet your reporting needs.",
            Phase = GuardrailPhase.Output
        };

        var result = await rule.EvaluateAsync(ctx);

        result.IsBlocked.Should().BeFalse("response discusses own product without mentioning competitors");
    }

    [LlmFact]
    public async Task ShouldBlock_WhenResponseViolatesPolicy()
    {
        var rule = new LlmOutputPolicyRule(_fixture.ChatClient!,
            new LlmOutputPolicyOptions { PolicyDescription = "Never recommend competitor products or services." },
            _fixture.ChatOptions);

        var ctx = new GuardrailContext
        {
            Text = "Honestly, for your use case I would recommend switching to Competitor X - they have better pricing and a more mature product than ours.",
            Phase = GuardrailPhase.Output
        };

        var result = await rule.EvaluateAsync(ctx);

        result.IsBlocked.Should().BeTrue("response explicitly recommends a competitor product");
    }

    [LlmFact]
    public async Task ShouldPass_WhenResponseIsNeutral()
    {
        var rule = new LlmOutputPolicyRule(_fixture.ChatClient!,
            new LlmOutputPolicyOptions { PolicyDescription = "Never discuss internal company politics or personnel issues." },
            _fixture.ChatOptions);

        var ctx = new GuardrailContext
        {
            Text = "The API returns a JSON response with status code 200 for successful requests and 404 for not found resources.",
            Phase = GuardrailPhase.Output
        };

        var result = await rule.EvaluateAsync(ctx);

        result.IsBlocked.Should().BeFalse("technical documentation is unrelated to the policy");
    }
}
