using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Rules.LLM;
using FluentAssertions;
using Microsoft.Extensions.AI;
using Moq;
using Xunit;

namespace AgentGuard.Core.Tests.Rules;

public class LlmGroundednessRuleTests
{
    private static GuardrailContext Ctx(string text, IReadOnlyList<ChatMessage>? messages = null)
        => new() { Text = text, Phase = GuardrailPhase.Output, Messages = messages };

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

    private static LlmGroundednessRule CreateRule(string response, GroundednessAction action = GroundednessAction.Block)
        => new(MockClient(response).Object, new LlmGroundednessOptions { Action = action });

    [Fact]
    public async Task ShouldPass_WhenLlmRespondsGrounded()
    {
        var rule = CreateRule("GROUNDED");

        var result = await rule.EvaluateAsync(Ctx("Your order shipped yesterday."));

        result.IsBlocked.Should().BeFalse();
    }

    [Fact]
    public async Task ShouldBlock_WhenLlmRespondsUngrounded()
    {
        var rule = CreateRule("UNGROUNDED|claim:the order was delivered on March 15th");

        var result = await rule.EvaluateAsync(Ctx("The order was delivered on March 15th."));

        result.IsBlocked.Should().BeTrue();
        result.Severity.Should().Be(GuardrailSeverity.Medium);
        result.Reason.Should().Contain("the order was delivered on March 15th");
    }

    [Fact]
    public async Task ShouldWarn_WhenActionIsWarn()
    {
        var rule = CreateRule("UNGROUNDED|claim:invented a statistic", action: GroundednessAction.Warn);

        var result = await rule.EvaluateAsync(Ctx("Statistics show 95% improvement."));

        result.IsBlocked.Should().BeFalse();
        result.Metadata.Should().NotBeNull();
        result.Metadata!["ungrounded_claim"].Should().Be("invented a statistic");
    }

    [Fact]
    public async Task ShouldIncludeConversationHistoryInPrompt()
    {
        IEnumerable<ChatMessage>? capturedMessages = null;
        var mock = new Mock<IChatClient>();
        mock.Setup(c => c.GetResponseAsync(
                It.IsAny<IEnumerable<ChatMessage>>(),
                It.IsAny<ChatOptions?>(),
                It.IsAny<CancellationToken>()))
            .Callback<IEnumerable<ChatMessage>, ChatOptions?, CancellationToken>((msgs, _, _) => capturedMessages = msgs.ToList())
            .ReturnsAsync(new ChatResponse(new ChatMessage(ChatRole.Assistant, "GROUNDED")));

        var rule = new LlmGroundednessRule(mock.Object);

        var messages = new List<ChatMessage>
        {
            new(ChatRole.User, "What is my order status?"),
            new(ChatRole.Assistant, "Your order #123 shipped yesterday.")
        };

        await rule.EvaluateAsync(Ctx("As I mentioned, your order #123 shipped yesterday.", messages));

        capturedMessages.Should().NotBeNull();
        var systemPrompt = capturedMessages!.First().Text!;
        systemPrompt.Should().Contain("What is my order status?");
        systemPrompt.Should().Contain("Your order #123 shipped yesterday.");
    }

    [Fact]
    public async Task ShouldHandleMissingMessages()
    {
        IEnumerable<ChatMessage>? capturedMessages = null;
        var mock = new Mock<IChatClient>();
        mock.Setup(c => c.GetResponseAsync(
                It.IsAny<IEnumerable<ChatMessage>>(),
                It.IsAny<ChatOptions?>(),
                It.IsAny<CancellationToken>()))
            .Callback<IEnumerable<ChatMessage>, ChatOptions?, CancellationToken>((msgs, _, _) => capturedMessages = msgs.ToList())
            .ReturnsAsync(new ChatResponse(new ChatMessage(ChatRole.Assistant, "GROUNDED")));

        var rule = new LlmGroundednessRule(mock.Object);

        await rule.EvaluateAsync(Ctx("Some response", messages: null));

        var systemPrompt = capturedMessages!.First().Text!;
        systemPrompt.Should().Contain("no conversation history available");
    }

    [Fact]
    public async Task ShouldPass_WhenLlmReturnsUnexpectedResponse()
    {
        var rule = CreateRule("I'm not sure about this");

        var result = await rule.EvaluateAsync(Ctx("some text"));

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

        var rule = new LlmGroundednessRule(mock.Object);

        var result = await rule.EvaluateAsync(Ctx("some text"));

        result.IsBlocked.Should().BeFalse();
    }

    [Fact]
    public async Task ShouldPass_EmptyInput()
    {
        var rule = CreateRule("GROUNDED");

        var result = await rule.EvaluateAsync(Ctx(""));

        result.IsBlocked.Should().BeFalse();
    }

    [Fact]
    public void ShouldHaveCorrectMetadata()
    {
        var rule = CreateRule("GROUNDED");
        rule.Name.Should().Be("llm-groundedness");
        rule.Phase.Should().Be(GuardrailPhase.Output);
        rule.Order.Should().Be(65);
    }

    [Fact]
    public void ShouldFormatConversationHistory()
    {
        var messages = new List<ChatMessage>
        {
            new(ChatRole.User, "Hello"),
            new(ChatRole.Assistant, "Hi there!")
        };

        var formatted = LlmGroundednessRule.FormatConversationHistory(messages);
        formatted.Should().Contain("User: Hello");
        formatted.Should().Contain("Assistant: Hi there!");
    }

    [Fact]
    public void ShouldParseClaim()
    {
        var claim = LlmGroundednessRule.ParseClaim("UNGROUNDED|claim:the product costs $99");
        claim.Should().Be("the product costs $99");
    }
}
