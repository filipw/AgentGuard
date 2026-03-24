using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Builders;
using AgentGuard.Core.Guardrails;
using FluentAssertions;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Xunit;

namespace AgentGuard.Core.Tests.Guardrails;

public class ReaskPipelineTests
{
    private static GuardrailContext OutputCtx(string text) => new() { Text = text, Phase = GuardrailPhase.Output };
    private static GuardrailContext InputCtx(string text) => new() { Text = text, Phase = GuardrailPhase.Input };

    [Fact]
    public async Task ShouldNotReask_WhenOutputPasses()
    {
        var chatClient = new Mock<IChatClient>();
        var rule = new TestRule("ok", GuardrailPhase.Output, _ => ValueTask.FromResult(GuardrailResult.Passed()));
        var policy = new GuardrailPolicy("t", [rule], reaskOptions: new ReaskOptions(), reaskChatClient: chatClient.Object);
        var pipeline = new GuardrailPipeline(policy, NullLogger<GuardrailPipeline>.Instance);

        var result = await pipeline.RunAsync(OutputCtx("fine response"));

        result.IsBlocked.Should().BeFalse();
        result.WasReasked.Should().BeFalse();
        result.ReaskAttemptsUsed.Should().Be(0);
        chatClient.Verify(c => c.GetResponseAsync(It.IsAny<IEnumerable<ChatMessage>>(), It.IsAny<ChatOptions>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task ShouldReask_WhenOutputBlocked_AndSecondAttemptPasses()
    {
        var callCount = 0;
        var rule = new TestRule("policy", GuardrailPhase.Output, ctx =>
        {
            callCount++;
            return ValueTask.FromResult(ctx.Text.Contains("bad")
                ? GuardrailResult.Blocked("contains bad word")
                : GuardrailResult.Passed());
        });

        var chatClient = new Mock<IChatClient>();
        chatClient.Setup(c => c.GetResponseAsync(It.IsAny<IEnumerable<ChatMessage>>(), It.IsAny<ChatOptions>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ChatResponse(new ChatMessage(ChatRole.Assistant, "good response")));

        var policy = new GuardrailPolicy("t", [rule], reaskOptions: new ReaskOptions { MaxAttempts = 1 }, reaskChatClient: chatClient.Object);
        var pipeline = new GuardrailPipeline(policy, NullLogger<GuardrailPipeline>.Instance);

        var result = await pipeline.RunAsync(OutputCtx("bad response"));

        result.IsBlocked.Should().BeFalse();
        result.WasReasked.Should().BeTrue();
        result.ReaskAttemptsUsed.Should().Be(1);
        result.FinalText.Should().Be("good response");
        callCount.Should().Be(2); // first eval + re-eval after reask
    }

    [Fact]
    public async Task ShouldReturnBlocked_WhenAllReaskAttemptsExhausted()
    {
        var rule = new TestRule("strict", GuardrailPhase.Output, _ => ValueTask.FromResult(GuardrailResult.Blocked("always blocked")));

        var chatClient = new Mock<IChatClient>();
        chatClient.Setup(c => c.GetResponseAsync(It.IsAny<IEnumerable<ChatMessage>>(), It.IsAny<ChatOptions>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ChatResponse(new ChatMessage(ChatRole.Assistant, "still bad")));

        var policy = new GuardrailPolicy("t", [rule], reaskOptions: new ReaskOptions { MaxAttempts = 3 }, reaskChatClient: chatClient.Object);
        var pipeline = new GuardrailPipeline(policy, NullLogger<GuardrailPipeline>.Instance);

        var result = await pipeline.RunAsync(OutputCtx("bad"));

        result.IsBlocked.Should().BeTrue();
        result.WasReasked.Should().BeTrue();
        result.ReaskAttemptsUsed.Should().Be(3);
        chatClient.Verify(c => c.GetResponseAsync(It.IsAny<IEnumerable<ChatMessage>>(), It.IsAny<ChatOptions>(), It.IsAny<CancellationToken>()), Times.Exactly(3));
    }

    [Fact]
    public async Task ShouldNotReask_WhenInputPhaseBlocked()
    {
        var rule = new TestRule("input-rule", GuardrailPhase.Input, _ => ValueTask.FromResult(GuardrailResult.Blocked("injection")));

        var chatClient = new Mock<IChatClient>();
        var policy = new GuardrailPolicy("t", [rule], reaskOptions: new ReaskOptions(), reaskChatClient: chatClient.Object);
        var pipeline = new GuardrailPipeline(policy, NullLogger<GuardrailPipeline>.Instance);

        var result = await pipeline.RunAsync(InputCtx("bad input"));

        result.IsBlocked.Should().BeTrue();
        result.WasReasked.Should().BeFalse();
        chatClient.Verify(c => c.GetResponseAsync(It.IsAny<IEnumerable<ChatMessage>>(), It.IsAny<ChatOptions>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task ShouldNotReask_WhenReaskNotEnabled()
    {
        var rule = new TestRule("strict", GuardrailPhase.Output, _ => ValueTask.FromResult(GuardrailResult.Blocked("blocked")));
        var policy = new GuardrailPolicy("t", [rule]); // no reask
        var pipeline = new GuardrailPipeline(policy, NullLogger<GuardrailPipeline>.Instance);

        var result = await pipeline.RunAsync(OutputCtx("bad"));

        result.IsBlocked.Should().BeTrue();
        result.WasReasked.Should().BeFalse();
        result.ReaskAttemptsUsed.Should().Be(0);
    }

    [Fact]
    public async Task ShouldSucceedOnSecondReaskAttempt_WhenFirstStillBlocked()
    {
        var rule = new TestRule("policy", GuardrailPhase.Output, ctx =>
        {
            return ValueTask.FromResult(ctx.Text.Contains("approved")
                ? GuardrailResult.Passed()
                : GuardrailResult.Blocked("not approved"));
        });

        var chatClient = new Mock<IChatClient>();
        chatClient.SetupSequence(c => c.GetResponseAsync(It.IsAny<IEnumerable<ChatMessage>>(), It.IsAny<ChatOptions>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ChatResponse(new ChatMessage(ChatRole.Assistant, "still bad")))
            .ReturnsAsync(new ChatResponse(new ChatMessage(ChatRole.Assistant, "approved answer")));

        var policy = new GuardrailPolicy("t", [rule], reaskOptions: new ReaskOptions { MaxAttempts = 3 }, reaskChatClient: chatClient.Object);
        var pipeline = new GuardrailPipeline(policy, NullLogger<GuardrailPipeline>.Instance);

        var result = await pipeline.RunAsync(OutputCtx("bad output"));

        result.IsBlocked.Should().BeFalse();
        result.WasReasked.Should().BeTrue();
        result.ReaskAttemptsUsed.Should().Be(2);
        result.FinalText.Should().Be("approved answer");
    }

    [Fact]
    public async Task ShouldPassChatOptions_ToReaskLlmCall()
    {
        var rule = new TestRule("strict", GuardrailPhase.Output, _ => ValueTask.FromResult(GuardrailResult.Blocked("blocked")));
        var chatOptions = new ChatOptions { Temperature = 0.1f };

        var chatClient = new Mock<IChatClient>();
        chatClient.Setup(c => c.GetResponseAsync(It.IsAny<IEnumerable<ChatMessage>>(), It.IsAny<ChatOptions>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ChatResponse(new ChatMessage(ChatRole.Assistant, "ok")));

        var policy = new GuardrailPolicy("t", [rule],
            reaskOptions: new ReaskOptions { MaxAttempts = 1, ChatOptions = chatOptions },
            reaskChatClient: chatClient.Object);
        var pipeline = new GuardrailPipeline(policy, NullLogger<GuardrailPipeline>.Instance);

        await pipeline.RunAsync(OutputCtx("bad"));

        chatClient.Verify(c => c.GetResponseAsync(It.IsAny<IEnumerable<ChatMessage>>(), chatOptions, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task ShouldIncludeBlockedResponseInReaskMessages_WhenEnabled()
    {
        var rule = new TestRule("strict", GuardrailPhase.Output, _ => ValueTask.FromResult(GuardrailResult.Blocked("bad content")));

        List<ChatMessage>? capturedMessages = null;
        var chatClient = new Mock<IChatClient>();
        chatClient.Setup(c => c.GetResponseAsync(It.IsAny<IEnumerable<ChatMessage>>(), It.IsAny<ChatOptions>(), It.IsAny<CancellationToken>()))
            .Callback<IEnumerable<ChatMessage>, ChatOptions?, CancellationToken>((msgs, _, _) => capturedMessages = msgs.ToList())
            .ReturnsAsync(new ChatResponse(new ChatMessage(ChatRole.Assistant, "fixed")));

        var policy = new GuardrailPolicy("t", [rule],
            reaskOptions: new ReaskOptions { MaxAttempts = 1, IncludeBlockedResponse = true },
            reaskChatClient: chatClient.Object);
        var pipeline = new GuardrailPipeline(policy, NullLogger<GuardrailPipeline>.Instance);

        await pipeline.RunAsync(OutputCtx("offensive content"));

        capturedMessages.Should().NotBeNull();
        capturedMessages!.Should().Contain(m => m.Role == ChatRole.Assistant && m.Text == "offensive content");
        capturedMessages!.Should().Contain(m => m.Role == ChatRole.System && m.Text!.Contains("bad content"));
    }

    [Fact]
    public async Task ShouldNotIncludeBlockedResponse_WhenDisabled()
    {
        var rule = new TestRule("strict", GuardrailPhase.Output, _ => ValueTask.FromResult(GuardrailResult.Blocked("bad")));

        List<ChatMessage>? capturedMessages = null;
        var chatClient = new Mock<IChatClient>();
        chatClient.Setup(c => c.GetResponseAsync(It.IsAny<IEnumerable<ChatMessage>>(), It.IsAny<ChatOptions>(), It.IsAny<CancellationToken>()))
            .Callback<IEnumerable<ChatMessage>, ChatOptions?, CancellationToken>((msgs, _, _) => capturedMessages = msgs.ToList())
            .ReturnsAsync(new ChatResponse(new ChatMessage(ChatRole.Assistant, "fixed")));

        var policy = new GuardrailPolicy("t", [rule],
            reaskOptions: new ReaskOptions { MaxAttempts = 1, IncludeBlockedResponse = false },
            reaskChatClient: chatClient.Object);
        var pipeline = new GuardrailPipeline(policy, NullLogger<GuardrailPipeline>.Instance);

        await pipeline.RunAsync(OutputCtx("offensive content"));

        capturedMessages.Should().NotBeNull();
        capturedMessages!.Should().NotContain(m => m.Role == ChatRole.Assistant);
    }

    [Fact]
    public async Task ShouldIncludeConversationHistory_InReaskMessages()
    {
        var rule = new TestRule("strict", GuardrailPhase.Output, _ => ValueTask.FromResult(GuardrailResult.Blocked("bad")));

        List<ChatMessage>? capturedMessages = null;
        var chatClient = new Mock<IChatClient>();
        chatClient.Setup(c => c.GetResponseAsync(It.IsAny<IEnumerable<ChatMessage>>(), It.IsAny<ChatOptions>(), It.IsAny<CancellationToken>()))
            .Callback<IEnumerable<ChatMessage>, ChatOptions?, CancellationToken>((msgs, _, _) => capturedMessages = msgs.ToList())
            .ReturnsAsync(new ChatResponse(new ChatMessage(ChatRole.Assistant, "fixed")));

        var policy = new GuardrailPolicy("t", [rule],
            reaskOptions: new ReaskOptions { MaxAttempts = 1 },
            reaskChatClient: chatClient.Object);
        var pipeline = new GuardrailPipeline(policy, NullLogger<GuardrailPipeline>.Instance);

        var ctx = new GuardrailContext
        {
            Text = "bad response",
            Phase = GuardrailPhase.Output,
            Messages = [new ChatMessage(ChatRole.User, "Tell me about billing")]
        };

        await pipeline.RunAsync(ctx);

        capturedMessages.Should().NotBeNull();
        capturedMessages!.Should().Contain(m => m.Role == ChatRole.User && m.Text == "Tell me about billing");
    }

    [Fact]
    public async Task ShouldWorkViaBuilder_EnableReask()
    {
        var chatClient = new Mock<IChatClient>();
        chatClient.Setup(c => c.GetResponseAsync(It.IsAny<IEnumerable<ChatMessage>>(), It.IsAny<ChatOptions>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ChatResponse(new ChatMessage(ChatRole.Assistant, "safe response")));

        var policy = new GuardrailPolicyBuilder()
            .AddRule(new TestRule("blocker", GuardrailPhase.Output, ctx =>
                ValueTask.FromResult(ctx.Text.Contains("unsafe")
                    ? GuardrailResult.Blocked("unsafe content")
                    : GuardrailResult.Passed())))
            .EnableReask(chatClient.Object, o => o.MaxAttempts = 2)
            .Build();

        var pipeline = new GuardrailPipeline(policy, NullLogger<GuardrailPipeline>.Instance);
        var result = await pipeline.RunAsync(OutputCtx("unsafe output"));

        result.IsBlocked.Should().BeFalse();
        result.WasReasked.Should().BeTrue();
        result.FinalText.Should().Be("safe response");
    }

    [Fact]
    public async Task ShouldRespectCancellation_DuringReask()
    {
        var rule = new TestRule("strict", GuardrailPhase.Output, _ => ValueTask.FromResult(GuardrailResult.Blocked("blocked")));

        var cts = new CancellationTokenSource();
        var chatClient = new Mock<IChatClient>();
        chatClient.Setup(c => c.GetResponseAsync(It.IsAny<IEnumerable<ChatMessage>>(), It.IsAny<ChatOptions>(), It.IsAny<CancellationToken>()))
            .Callback<IEnumerable<ChatMessage>, ChatOptions?, CancellationToken>((_, _, _) => cts.Cancel())
            .ThrowsAsync(new OperationCanceledException());

        var policy = new GuardrailPolicy("t", [rule],
            reaskOptions: new ReaskOptions { MaxAttempts = 3 },
            reaskChatClient: chatClient.Object);
        var pipeline = new GuardrailPipeline(policy, NullLogger<GuardrailPipeline>.Instance);

        var act = () => pipeline.RunAsync(OutputCtx("bad"), cts.Token).AsTask();
        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    private class TestRule(string name, GuardrailPhase phase, Func<GuardrailContext, ValueTask<GuardrailResult>> eval) : IGuardrailRule
    {
        public string Name => name;
        public GuardrailPhase Phase => phase;
        public int Order => 100;
        public ValueTask<GuardrailResult> EvaluateAsync(GuardrailContext context, CancellationToken ct = default) => eval(context);
    }
}
