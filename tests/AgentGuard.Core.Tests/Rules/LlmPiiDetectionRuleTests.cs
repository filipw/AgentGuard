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

    // a rule configured to Redact only ever redacts or errors

    [Fact]
    public async Task ShouldReportError_WhenRedactRuleGetsOffFormatResponse()
    {
        var rule = new LlmPiiDetectionRule(MockClient("This message contains PII elements").Object);

        var result = await rule.EvaluateAsync(Ctx("test"));

        result.IsError.Should().BeTrue();
        result.IsBlocked.Should().BeFalse("a Redact rule must not silently become a Block");
        result.IsModified.Should().BeFalse();
    }

    [Fact]
    public async Task ShouldBlock_WhenBlockRuleGetsPiiVerdict()
    {
        var rule = new LlmPiiDetectionRule(
            MockClient("PII").Object, new LlmPiiDetectionOptions { Action = PiiAction.Block });

        var result = await rule.EvaluateAsync(Ctx("test"));

        result.IsBlocked.Should().BeTrue();
    }

    // Redact read only the first line of the judge's reply, so a multi-line message came back cut
    // to its first line, and "REDACTED:" on a line of its own was treated as off-format - which
    // fails open with the PII still in the text.

    private const string MultiLineInput = "Hi, I'm John Smith.\nMy order 4411 never arrived.\nPlease refund it to my card.";
    private const string MultiLineRedacted = "Hi, I'm [REDACTED].\nMy order 4411 never arrived.\nPlease refund it to my card.";

    [Fact]
    public async Task ShouldKeepEveryLine_WhenRedactingAMultiLineMessage()
    {
        var rule = new LlmPiiDetectionRule(MockClient("REDACTED: " + MultiLineRedacted).Object);

        var result = await rule.EvaluateAsync(Ctx(MultiLineInput));

        result.IsModified.Should().BeTrue();
        result.ModifiedText.Should().Be(MultiLineRedacted);
    }

    [Theory]
    [InlineData("REDACTED:\n" + MultiLineRedacted)]
    [InlineData("REDACTED:\r\n" + MultiLineRedacted + "\r\n")]
    [InlineData("```\nREDACTED: " + MultiLineRedacted + "\n```")]
    [InlineData("<think>The name is PII.</think>\nREDACTED:\n" + MultiLineRedacted)]
    [InlineData("REDACTED:\n```text\n" + MultiLineRedacted + "\n```")]
    [InlineData("redacted:   " + MultiLineRedacted + "\n\n")]
    public async Task ShouldRedact_WhenTheMessageFollowsTheMarkerInAnyAcceptedLayout(string reply)
    {
        var rule = new LlmPiiDetectionRule(MockClient(reply).Object);

        var result = await rule.EvaluateAsync(Ctx(MultiLineInput));

        result.IsError.Should().BeFalse();
        result.IsModified.Should().BeTrue();
        result.ModifiedText.Should().Be(MultiLineRedacted);
    }

    [Fact]
    public async Task ShouldKeepTheMessagesOwnFence_WhenTheInputIsAFencedBlock()
    {
        var rule = new LlmPiiDetectionRule(MockClient("REDACTED:\n```\nssn: [REDACTED]\n```").Object);

        var result = await rule.EvaluateAsync(Ctx("```\nssn: 123-45-6789\n```"));

        result.ModifiedText.Should().Be("```\nssn: [REDACTED]\n```");
    }

    [Theory]
    [InlineData("CLEAN")]
    [InlineData("```\nCLEAN\n```")]
    [InlineData("<think>no names, no numbers</think>\nCLEAN")]
    public async Task ShouldPass_WhenTheCleanVerdictIsWrapped(string reply)
    {
        var rule = new LlmPiiDetectionRule(MockClient(reply).Object);

        var result = await rule.EvaluateAsync(Ctx(MultiLineInput));

        result.IsError.Should().BeFalse();
        result.IsModified.Should().BeFalse();
        result.IsBlocked.Should().BeFalse();
    }

    [Theory]
    [InlineData("REDACTED:")]
    [InlineData("REDACTED:\n\n")]
    [InlineData("Sure! Here is the message:\nREDACTED: Hi, I'm [REDACTED].")]
    public async Task ShouldReportError_WhenTheRedactedReplyCarriesNoMessage(string reply)
    {
        var rule = new LlmPiiDetectionRule(MockClient(reply).Object);

        var result = await rule.EvaluateAsync(Ctx(MultiLineInput));

        result.IsError.Should().BeTrue();
        result.IsModified.Should().BeFalse();
        result.IsBlocked.Should().BeFalse();
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
