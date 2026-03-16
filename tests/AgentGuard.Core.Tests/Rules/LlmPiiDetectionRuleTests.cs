using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Rules.LLM;
using FluentAssertions;
using Microsoft.Extensions.AI;
using Moq;
using Xunit;

namespace AgentGuard.Core.Tests.Rules;

public class LlmPiiDetectionRuleTests
{
    private static GuardrailContext Ctx(string text, GuardrailPhase phase = GuardrailPhase.Input)
        => new() { Text = text, Phase = phase };

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

    [Fact]
    public async Task ShouldPass_WhenLlmRespondsClean()
    {
        var rule = new LlmPiiDetectionRule(MockClient("CLEAN").Object);

        var result = await rule.EvaluateAsync(Ctx("What time is it?"));

        result.IsBlocked.Should().BeFalse();
        result.IsModified.Should().BeFalse();
    }

    [Fact]
    public async Task ShouldRedact_WhenLlmReturnsRedactedText()
    {
        var rule = new LlmPiiDetectionRule(MockClient("REDACTED: My name is [REDACTED] and my email is [REDACTED]").Object);

        var result = await rule.EvaluateAsync(Ctx("My name is John Smith and my email is john@example.com"));

        result.IsModified.Should().BeTrue();
        result.ModifiedText.Should().Be("My name is [REDACTED] and my email is [REDACTED]");
    }

    [Fact]
    public async Task ShouldBlock_WhenActionIsBlock_AndPiiDetected()
    {
        var options = new LlmPiiDetectionOptions { Action = PiiAction.Block };
        var rule = new LlmPiiDetectionRule(MockClient("PII").Object, options);

        var result = await rule.EvaluateAsync(Ctx("My SSN is 123-45-6789"));

        result.IsBlocked.Should().BeTrue();
        result.Severity.Should().Be(GuardrailSeverity.High);
    }

    [Fact]
    public async Task ShouldPass_WhenActionIsBlock_AndNoDetected()
    {
        var options = new LlmPiiDetectionOptions { Action = PiiAction.Block };
        var rule = new LlmPiiDetectionRule(MockClient("CLEAN").Object, options);

        var result = await rule.EvaluateAsync(Ctx("The weather is nice today"));

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
            .ThrowsAsync(new HttpRequestException("timeout"));

        var rule = new LlmPiiDetectionRule(mock.Object);

        var result = await rule.EvaluateAsync(Ctx("My SSN is 123-45-6789"));

        result.IsBlocked.Should().BeFalse();
    }

    [Fact]
    public async Task ShouldBlock_WhenUnparsableResponseContainsPii()
    {
        var rule = new LlmPiiDetectionRule(MockClient("This message contains PII elements").Object);

        var result = await rule.EvaluateAsync(Ctx("test"));

        result.IsBlocked.Should().BeTrue();
    }

    [Fact]
    public async Task ShouldPass_EmptyInput()
    {
        var rule = new LlmPiiDetectionRule(MockClient("CLEAN").Object);

        var result = await rule.EvaluateAsync(Ctx(""));

        result.IsBlocked.Should().BeFalse();
        result.IsModified.Should().BeFalse();
    }

    [Fact]
    public void ShouldHaveCorrectMetadata()
    {
        var rule = new LlmPiiDetectionRule(MockClient("CLEAN").Object);
        rule.Name.Should().Be("llm-pii-detection");
        rule.Phase.Should().Be(GuardrailPhase.Both);
        rule.Order.Should().Be(25);
    }

    [Fact]
    public void ShouldHaveDifferentPromptsForBlockAndRedact()
    {
        var blockPrompt = LlmPiiDetectionRule.GetDefaultPrompt(PiiAction.Block);
        var redactPrompt = LlmPiiDetectionRule.GetDefaultPrompt(PiiAction.Redact);

        blockPrompt.Should().NotBe(redactPrompt);
        blockPrompt.Should().Contain("CLEAN");
        blockPrompt.Should().Contain("PII");
        redactPrompt.Should().Contain("REDACTED");
    }
}
