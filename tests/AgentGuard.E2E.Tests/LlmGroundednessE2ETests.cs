using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Rules.LLM;
using FluentAssertions;
using Microsoft.Extensions.AI;
using Xunit;

namespace AgentGuard.E2E.Tests;

public sealed class LlmGroundednessE2ETests : IClassFixture<LlmTestFixture>
{
    private readonly LlmTestFixture _fixture;

    public LlmGroundednessE2ETests(LlmTestFixture fixture) => _fixture = fixture;

    [LlmFact]
    public async Task ShouldPass_WhenResponseIsGroundedInContext()
    {
        var rule = new LlmGroundednessRule(_fixture.ChatClient!, chatOptions: _fixture.ChatOptions);

        var messages = new List<ChatMessage>
        {
            new(ChatRole.User, "What is the status of my order #12345?"),
            new(ChatRole.Assistant, "Let me check. Your order #12345 was shipped on March 10th via FedEx.")
        };

        var ctx = new GuardrailContext
        {
            Text = "As I mentioned, your order #12345 was shipped on March 10th via FedEx. You should receive it within 3-5 business days.",
            Phase = GuardrailPhase.Output,
            Messages = messages
        };

        var result = await rule.EvaluateAsync(ctx);

        result.IsBlocked.Should().BeFalse("response is grounded in the conversation history");
    }

    [LlmFact]
    public async Task ShouldBlock_WhenResponseFabricatesFacts()
    {
        var rule = new LlmGroundednessRule(_fixture.ChatClient!, chatOptions: _fixture.ChatOptions);

        var messages = new List<ChatMessage>
        {
            new(ChatRole.User, "Tell me about your pricing plans.")
        };

        var ctx = new GuardrailContext
        {
            Text = "Our Enterprise plan costs exactly $4,999 per month and includes 500 API calls per second, 24/7 phone support, and a dedicated account manager named Sarah Johnson who has 15 years of experience.",
            Phase = GuardrailPhase.Output,
            Messages = messages
        };

        var result = await rule.EvaluateAsync(ctx);

        result.IsBlocked.Should().BeTrue("response fabricates specific pricing, names, and details not in conversation context");
    }

    [LlmFact]
    public async Task ShouldPass_WhenResponseUsesCommonKnowledge()
    {
        var rule = new LlmGroundednessRule(_fixture.ChatClient!, chatOptions: _fixture.ChatOptions);

        var ctx = new GuardrailContext
        {
            Text = "Water boils at 100 degrees Celsius at standard atmospheric pressure. This is a fundamental property of water.",
            Phase = GuardrailPhase.Output,
            Messages = []
        };

        var result = await rule.EvaluateAsync(ctx);

        result.IsBlocked.Should().BeFalse("common knowledge facts should be considered grounded");
    }
}
