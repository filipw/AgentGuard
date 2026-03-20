using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Rules.LLM;
using FluentAssertions;
using Microsoft.Extensions.AI;
using Moq;
using Xunit;

namespace AgentGuard.Core.Tests.Rules;

public class LlmCopyrightRuleTests
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

    private static LlmCopyrightRule CreateRule(string response, CopyrightAction action = CopyrightAction.Block)
        => new(MockClient(response).Object, new LlmCopyrightOptions { Action = action });

    [Fact]
    public async Task ShouldPass_WhenLlmRespondsClean()
    {
        var rule = CreateRule("CLEAN");

        var result = await rule.EvaluateAsync(Ctx("Here's how to implement a binary search algorithm."));

        result.IsBlocked.Should().BeFalse();
    }

    [Fact]
    public async Task ShouldBlock_WhenLlmRespondsCopyright()
    {
        var rule = CreateRule("COPYRIGHT|source:Beatles - Yesterday|type:lyrics");

        var result = await rule.EvaluateAsync(Ctx("Yesterday, all my troubles seemed so far away..."));

        result.IsBlocked.Should().BeTrue();
        result.Severity.Should().Be(GuardrailSeverity.High);
        result.Reason.Should().Contain("Beatles - Yesterday");
        result.Metadata.Should().NotBeNull();
        result.Metadata!["copyright_source"].Should().Be("Beatles - Yesterday");
        result.Metadata["copyright_type"].Should().Be("lyrics");
    }

    [Fact]
    public async Task ShouldWarn_WhenActionIsWarn()
    {
        var rule = CreateRule("COPYRIGHT|source:J.K. Rowling - Harry Potter|type:book", action: CopyrightAction.Warn);

        var result = await rule.EvaluateAsync(Ctx("Mr. Dursley of number four, Privet Drive..."));

        result.IsBlocked.Should().BeFalse();
        result.Metadata.Should().NotBeNull();
        result.Metadata!["copyright_source"].Should().Be("J.K. Rowling - Harry Potter");
        result.Metadata["copyright_type"].Should().Be("book");
    }

    [Fact]
    public async Task ShouldParseSourceAndType()
    {
        var (source, type) = LlmCopyrightRule.ParseFields("COPYRIGHT|source:Bob Dylan - Blowin in the Wind|type:lyrics");
        source.Should().Be("Bob Dylan - Blowin in the Wind");
        type.Should().Be("lyrics");
    }

    [Fact]
    public async Task ShouldHandlePartialParse()
    {
        var (source, type) = LlmCopyrightRule.ParseFields("COPYRIGHT|source:unknown work");
        source.Should().Be("unknown work");
        type.Should().Be("unknown");
    }

    [Fact]
    public async Task ShouldBlock_WhenOnlySourcePresent()
    {
        var rule = CreateRule("COPYRIGHT|source:some author");

        var result = await rule.EvaluateAsync(Ctx("copied content"));

        result.IsBlocked.Should().BeTrue();
        result.Metadata!["copyright_source"].Should().Be("some author");
        result.Metadata["copyright_type"].Should().Be("unknown");
    }

    [Fact]
    public async Task ShouldPass_WhenLlmReturnsUnexpectedResponse()
    {
        var rule = CreateRule("This content looks fine to me");

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

        var rule = new LlmCopyrightRule(mock.Object);

        var result = await rule.EvaluateAsync(Ctx("some text"));

        result.IsBlocked.Should().BeFalse();
    }

    [Fact]
    public async Task ShouldPass_EmptyInput()
    {
        var rule = CreateRule("CLEAN");

        var result = await rule.EvaluateAsync(Ctx(""));

        result.IsBlocked.Should().BeFalse();
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
            .ReturnsAsync(new ChatResponse(new ChatMessage(ChatRole.Assistant, "CLEAN")));

        var rule = new LlmCopyrightRule(mock.Object,
            new LlmCopyrightOptions { SystemPrompt = "Custom copyright check prompt." });

        await rule.EvaluateAsync(Ctx("test"));

        var systemPrompt = capturedMessages!.First().Text!;
        systemPrompt.Should().Be("Custom copyright check prompt.");
    }

    [Fact]
    public void ShouldHaveCorrectMetadata()
    {
        var rule = CreateRule("CLEAN");
        rule.Name.Should().Be("llm-copyright");
        rule.Phase.Should().Be(GuardrailPhase.Output);
        rule.Order.Should().Be(75);
    }

    [Fact]
    public async Task ShouldNotFalsePositive_WhenCleanResponseMentionsCopyright()
    {
        // Edge case: LLM says "CLEAN" but the word "copyright" appears somewhere
        var rule = CreateRule("CLEAN - no copyright issues found");

        var result = await rule.EvaluateAsync(Ctx("some text"));

        result.IsBlocked.Should().BeFalse();
    }
}
