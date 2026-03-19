using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Rules.LLM;
using FluentAssertions;
using Xunit;

namespace AgentGuard.E2E.Tests;

/// <summary>
/// End-to-end tests for <see cref="LlmTopicGuardrailRule"/> against a real LLM.
/// </summary>
public class LlmTopicGuardrailE2ETests : IClassFixture<LlmTestFixture>
{
    private readonly LlmTestFixture _fixture;

    public LlmTopicGuardrailE2ETests(LlmTestFixture fixture) => _fixture = fixture;

    [LlmFact]
    public async Task ShouldPass_OnTopicMessage()
    {
        var rule = new LlmTopicGuardrailRule(_fixture.ChatClient!,
            new LlmTopicGuardrailOptions { AllowedTopics = ["billing", "payments", "invoices"] },
            chatOptions: _fixture.ChatOptions);
        var ctx = new GuardrailContext { Text = "I need to update the payment method on my account.", Phase = GuardrailPhase.Input };

        var result = await rule.EvaluateAsync(ctx);
        result.IsBlocked.Should().BeFalse("billing-related question should be on-topic");
    }

    [LlmFact]
    public async Task ShouldBlock_OffTopicMessage()
    {
        var rule = new LlmTopicGuardrailRule(_fixture.ChatClient!,
            new LlmTopicGuardrailOptions { AllowedTopics = ["billing", "payments", "invoices"] },
            chatOptions: _fixture.ChatOptions);
        var ctx = new GuardrailContext { Text = "What is the recipe for chocolate cake?", Phase = GuardrailPhase.Input };

        var result = await rule.EvaluateAsync(ctx);
        result.IsBlocked.Should().BeTrue("recipe question is off-topic for billing agent");
    }

    [LlmFact]
    public async Task ShouldPass_RelatedTopic()
    {
        var rule = new LlmTopicGuardrailRule(_fixture.ChatClient!,
            new LlmTopicGuardrailOptions { AllowedTopics = ["technical support", "troubleshooting", "product issues"] },
            chatOptions: _fixture.ChatOptions);
        var ctx = new GuardrailContext { Text = "My laptop won't connect to WiFi after the latest update.", Phase = GuardrailPhase.Input };

        var result = await rule.EvaluateAsync(ctx);
        result.IsBlocked.Should().BeFalse("troubleshooting request should be on-topic");
    }

    [LlmFact]
    public async Task ShouldBlock_CompletelyUnrelated()
    {
        var rule = new LlmTopicGuardrailRule(_fixture.ChatClient!,
            new LlmTopicGuardrailOptions { AllowedTopics = ["healthcare", "medical appointments", "prescriptions"] },
            chatOptions: _fixture.ChatOptions);
        var ctx = new GuardrailContext { Text = "Who won the World Cup in 2022?", Phase = GuardrailPhase.Input };

        var result = await rule.EvaluateAsync(ctx);
        result.IsBlocked.Should().BeTrue("sports question is off-topic for healthcare agent");
    }

    [LlmFact]
    public async Task ShouldPass_BroadlyRelated()
    {
        var rule = new LlmTopicGuardrailRule(_fixture.ChatClient!,
            new LlmTopicGuardrailOptions { AllowedTopics = ["customer service", "account management"] },
            chatOptions: _fixture.ChatOptions);
        var ctx = new GuardrailContext { Text = "I'd like to change my shipping address.", Phase = GuardrailPhase.Input };

        var result = await rule.EvaluateAsync(ctx);
        result.IsBlocked.Should().BeFalse("account update is related to account management");
    }
}
