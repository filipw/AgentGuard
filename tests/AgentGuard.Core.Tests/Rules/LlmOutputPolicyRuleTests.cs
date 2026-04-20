using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Rules.LLM;
using FluentAssertions;
using Microsoft.Extensions.AI;
using Moq;
using Xunit;

namespace AgentGuard.Core.Tests.Rules;

public class LlmOutputPolicyRuleTests
{
    private static GuardrailContext Ctx(string text) => new() { Text = text, Phase = GuardrailPhase.Output };

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

    private static LlmOutputPolicyRule CreateRule(string response, string policy = "never recommend competitors",
        OutputPolicyAction action = OutputPolicyAction.Block)
        => new(MockClient(response).Object, new LlmOutputPolicyOptions { PolicyDescription = policy, Action = action });

    [Fact]
    public async Task ShouldPass_WhenLlmRespondsCompliant()
    {
        var rule = CreateRule("COMPLIANT");

        var result = await rule.EvaluateAsync(Ctx("Our product supports features X, Y, and Z."));

        result.IsBlocked.Should().BeFalse();
    }

    [Fact]
    public async Task ShouldBlock_WhenLlmRespondsViolation()
    {
        var rule = CreateRule("VIOLATION|reason:recommends competitor product Acme Corp");

        var result = await rule.EvaluateAsync(Ctx("You should try Acme Corp instead."));

        result.IsBlocked.Should().BeTrue();
        result.Severity.Should().Be(GuardrailSeverity.Medium);
        result.Reason.Should().Contain("recommends competitor product Acme Corp");
    }

    [Fact]
    public async Task ShouldWarn_WhenActionIsWarn()
    {
        var rule = CreateRule("VIOLATION|reason:mentions competitor pricing", action: OutputPolicyAction.Warn);

        var result = await rule.EvaluateAsync(Ctx("Competitor X charges less."));

        result.IsBlocked.Should().BeFalse();
        result.Metadata.Should().NotBeNull();
        result.Metadata!["violation_reason"].Should().Be("mentions competitor pricing");
        result.Metadata["policy"].Should().Be("never recommend competitors");
    }

    [Fact]
    public async Task ShouldParseReasonFromViolation()
    {
        var reason = LlmOutputPolicyRule.ParseReason("VIOLATION|reason:this is the specific reason");
        reason.Should().Be("this is the specific reason");
    }

    [Fact]
    public async Task ShouldReturnDefaultReason_WhenReasonFieldMissing()
    {
        var reason = LlmOutputPolicyRule.ParseReason("VIOLATION");
        reason.Should().Be("Policy violation detected.");
    }

    [Fact]
    public async Task ShouldPass_WhenLlmReturnsUnexpectedResponse()
    {
        var rule = CreateRule("I'm not sure about this response");

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

        var rule = new LlmOutputPolicyRule(mock.Object,
            new LlmOutputPolicyOptions { PolicyDescription = "test policy" });

        var result = await rule.EvaluateAsync(Ctx("some text"));

        result.IsBlocked.Should().BeFalse();
    }

    [Fact]
    public async Task ShouldPass_EmptyInput()
    {
        var rule = CreateRule("COMPLIANT");

        var result = await rule.EvaluateAsync(Ctx(""));

        result.IsBlocked.Should().BeFalse();
    }

    [Fact]
    public async Task ShouldIncludePolicyInSystemPrompt()
    {
        IEnumerable<ChatMessage>? capturedMessages = null;
        var mock = new Mock<IChatClient>();
        mock.Setup(c => c.GetResponseAsync(
                It.IsAny<IEnumerable<ChatMessage>>(),
                It.IsAny<ChatOptions?>(),
                It.IsAny<CancellationToken>()))
            .Callback<IEnumerable<ChatMessage>, ChatOptions?, CancellationToken>((msgs, _, _) => capturedMessages = msgs.ToList())
            .ReturnsAsync(new ChatResponse(new ChatMessage(ChatRole.Assistant, "COMPLIANT")));

        var rule = new LlmOutputPolicyRule(mock.Object,
            new LlmOutputPolicyOptions { PolicyDescription = "never discuss competitor products" });

        await rule.EvaluateAsync(Ctx("test response"));

        capturedMessages.Should().NotBeNull();
        var systemPrompt = capturedMessages!.First().Text!;
        systemPrompt.Should().Contain("never discuss competitor products");
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
            .ReturnsAsync(new ChatResponse(new ChatMessage(ChatRole.Assistant, "COMPLIANT")));

        var rule = new LlmOutputPolicyRule(mock.Object,
            new LlmOutputPolicyOptions
            {
                PolicyDescription = "no competitors",
                SystemPrompt = "Check policy: {policy}. Reply COMPLIANT or VIOLATION."
            });

        await rule.EvaluateAsync(Ctx("test"));

        var systemPrompt = capturedMessages!.First().Text!;
        systemPrompt.Should().Be("Check policy: no competitors. Reply COMPLIANT or VIOLATION.");
    }

    [Fact]
    public void ShouldHaveCorrectMetadata()
    {
        var rule = CreateRule("COMPLIANT");
        rule.Name.Should().Be("llm-output-policy");
        rule.Phase.Should().Be(GuardrailPhase.Output);
        rule.Order.Should().Be(55);
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
            .ReturnsAsync(new ChatResponse(new ChatMessage(ChatRole.Assistant, "COMPLIANT")));

        var rule = new LlmOutputPolicyRule(mock.Object,
            new LlmOutputPolicyOptions { PolicyDescription = "Never recommend competitors" });

        var ctx = new GuardrailContext
        {
            Text = "I'd suggest trying CompetitorCo instead.",
            Phase = GuardrailPhase.Output,
            Messages =
            [
                new(ChatRole.User, "What product should I use for data analytics?"),
                new(ChatRole.Assistant, "I'd suggest trying CompetitorCo instead.")
            ]
        };

        await rule.EvaluateAsync(ctx);

        var systemPrompt = capturedMessages!.First().Text!;
        systemPrompt.Should().Contain("Conversation history");
        systemPrompt.Should().Contain("What product should I use for data analytics?");
    }

    [Fact]
    public async Task ShouldWorkWithoutConversationHistory()
    {
        IEnumerable<ChatMessage>? capturedMessages = null;
        var mock = new Mock<IChatClient>();
        mock.Setup(c => c.GetResponseAsync(
                It.IsAny<IEnumerable<ChatMessage>>(),
                It.IsAny<ChatOptions?>(),
                It.IsAny<CancellationToken>()))
            .Callback<IEnumerable<ChatMessage>, ChatOptions?, CancellationToken>((msgs, _, _) => capturedMessages = msgs.ToList())
            .ReturnsAsync(new ChatResponse(new ChatMessage(ChatRole.Assistant, "COMPLIANT")));

        var rule = new LlmOutputPolicyRule(mock.Object,
            new LlmOutputPolicyOptions { PolicyDescription = "Never recommend competitors" });

        await rule.EvaluateAsync(Ctx("Our product is the best choice."));

        var systemPrompt = capturedMessages!.First().Text!;
        systemPrompt.Should().NotContain("Conversation history");
    }
}
