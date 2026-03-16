using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Rules.LLM;
using FluentAssertions;
using Microsoft.Extensions.AI;
using Moq;
using Xunit;

namespace AgentGuard.Core.Tests.Rules;

public class LlmTopicGuardrailRuleTests
{
    private static GuardrailContext Ctx(string text) => new() { Text = text, Phase = GuardrailPhase.Input };

    private static Mock<IChatClient> MockClient(string response)
    {
        var mock = new Mock<IChatClient>();
        mock.Setup(c => c.GetResponseAsync(
                It.IsAny<IEnumerable<ChatMessage>>(),
                It.IsAny<ChatOptions?>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ChatResponse(new ChatMessage(ChatRole.Assistant, response)));
        return mock;
    }

    private static LlmTopicGuardrailRule CreateRule(string response, params string[] topics)
        => new(MockClient(response).Object, new LlmTopicGuardrailOptions { AllowedTopics = topics.ToList() });

    [Fact]
    public async Task ShouldPass_WhenLlmRespondsOnTopic()
    {
        var rule = CreateRule("ON_TOPIC", "billing", "payments");

        var result = await rule.EvaluateAsync(Ctx("What is my invoice total?"));

        result.IsBlocked.Should().BeFalse();
    }

    [Fact]
    public async Task ShouldBlock_WhenLlmRespondsOffTopic()
    {
        var rule = CreateRule("OFF_TOPIC", "billing", "payments");

        var result = await rule.EvaluateAsync(Ctx("Tell me a joke about cats"));

        result.IsBlocked.Should().BeTrue();
        result.Severity.Should().Be(GuardrailSeverity.Medium);
        result.Reason.Should().Contain("billing");
    }

    [Fact]
    public async Task ShouldPass_WhenLlmReturnsUnexpectedResponse()
    {
        var rule = CreateRule("I cannot determine the topic", "billing");

        var result = await rule.EvaluateAsync(Ctx("hello"));

        result.IsBlocked.Should().BeFalse();
    }

    [Fact]
    public async Task ShouldFailOpen_WhenLlmCallFails()
    {
        var mock = new Mock<IChatClient>();
        mock.Setup(c => c.GetResponseAsync(
                It.IsAny<IEnumerable<ChatMessage>>(),
                It.IsAny<ChatOptions?>(),
                It.IsAny<CancellationToken>()))
            .ThrowsAsync(new HttpRequestException("connection refused"));

        var rule = new LlmTopicGuardrailRule(mock.Object,
            new LlmTopicGuardrailOptions { AllowedTopics = ["billing"] });

        var result = await rule.EvaluateAsync(Ctx("Tell me a joke"));

        result.IsBlocked.Should().BeFalse();
    }

    [Fact]
    public async Task ShouldPass_EmptyInput()
    {
        var rule = CreateRule("ON_TOPIC", "billing");

        var result = await rule.EvaluateAsync(Ctx(""));

        result.IsBlocked.Should().BeFalse();
    }

    [Fact]
    public async Task ShouldIncludeTopicsInSystemPrompt()
    {
        IEnumerable<ChatMessage>? capturedMessages = null;
        var mock = new Mock<IChatClient>();
        mock.Setup(c => c.GetResponseAsync(
                It.IsAny<IEnumerable<ChatMessage>>(),
                It.IsAny<ChatOptions?>(),
                It.IsAny<CancellationToken>()))
            .Callback<IEnumerable<ChatMessage>, ChatOptions?, CancellationToken>((msgs, _, _) => capturedMessages = msgs.ToList())
            .ReturnsAsync(new ChatResponse(new ChatMessage(ChatRole.Assistant, "ON_TOPIC")));

        var rule = new LlmTopicGuardrailRule(mock.Object,
            new LlmTopicGuardrailOptions { AllowedTopics = ["billing", "payments", "invoices"] });

        await rule.EvaluateAsync(Ctx("test"));

        capturedMessages.Should().NotBeNull();
        var systemPrompt = capturedMessages!.First().Text!;
        systemPrompt.Should().Contain("billing");
        systemPrompt.Should().Contain("payments");
        systemPrompt.Should().Contain("invoices");
    }

    [Fact]
    public async Task ShouldSupportCustomSystemPrompt()
    {
        IEnumerable<ChatMessage>? capturedMessages = null;
        var mock = new Mock<IChatClient>();
        mock.Setup(c => c.GetResponseAsync(
                It.IsAny<IEnumerable<ChatMessage>>(),
                It.IsAny<ChatOptions?>(),
                It.IsAny<CancellationToken>()))
            .Callback<IEnumerable<ChatMessage>, ChatOptions?, CancellationToken>((msgs, _, _) => capturedMessages = msgs.ToList())
            .ReturnsAsync(new ChatResponse(new ChatMessage(ChatRole.Assistant, "ON_TOPIC")));

        var rule = new LlmTopicGuardrailRule(mock.Object,
            new LlmTopicGuardrailOptions
            {
                AllowedTopics = ["billing"],
                SystemPrompt = "Only allow messages about {topics}. Reply ON_TOPIC or OFF_TOPIC."
            });

        await rule.EvaluateAsync(Ctx("test"));

        var systemPrompt = capturedMessages!.First().Text!;
        systemPrompt.Should().Be("Only allow messages about billing. Reply ON_TOPIC or OFF_TOPIC.");
    }

    [Fact]
    public void ShouldHaveCorrectMetadata()
    {
        var rule = CreateRule("ON_TOPIC", "billing");
        rule.Name.Should().Be("llm-topic-boundary");
        rule.Phase.Should().Be(GuardrailPhase.Input);
        rule.Order.Should().Be(35);
    }
}
