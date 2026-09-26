using System.Collections.ObjectModel;
using AgentGuard.AgentFramework.Workflows;
using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Guardrails;
using AgentGuard.Core.Ledger;
using AgentGuard.Pii;
using FluentAssertions;
using Microsoft.Agents.AI;
using Microsoft.Agents.AI.Workflows;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace AgentGuard.AgentFramework.Workflows.Tests;

// chat payloads are guarded message by message, and a rewrite replaces only the text it changed
public class GuardedExecutorChatTests
{
    private const string Email = "john@example.com";
    private const string Redacted = "<EMAIL_ADDRESS>";

    private static readonly DateTimeOffset CreatedAt = new(2026, 9, 26, 8, 30, 0, TimeSpan.Zero);

    [Fact]
    public async Task ShouldDeliverRedactedListWithAttachmentAndMetadata_WhenWorkflowSendsChatMessages()
    {
        var photo = new DataContent(new byte[] { 1, 2, 3 }, "image/png");
        var message = new ChatMessage(ChatRole.User, [new TextContent($"my email is {Email}, photo attached"), photo])
        {
            AuthorName = "alice",
            MessageId = "m1",
            CreatedAt = CreatedAt,
            AdditionalProperties = new() { ["channel"] = "web" }
        };
        var inner = new ChatListExecutor("chat");
        var guarded = inner.WithGuardrails(b => b.RedactPii());
        var workflow = new WorkflowBuilder(guarded).WithOutputFrom(guarded).Build();

        await using var run = await InProcessExecution.RunAsync(workflow, new List<ChatMessage> { message });

        run.OutgoingEvents.Where(e => e is WorkflowErrorEvent or ExecutorFailedEvent).Should().BeEmpty();
        var received = inner.Received.Should().ContainSingle().Subject;
        received.Should().BeOfType<List<ChatMessage>>();

        var delivered = received.Should().ContainSingle().Subject;
        delivered.Text.Should().Be($"my email is {Redacted}, photo attached");
        delivered.Contents.OfType<DataContent>().Should().ContainSingle().Which.Should().BeSameAs(photo);
        delivered.Role.Should().Be(ChatRole.User);
        delivered.AuthorName.Should().Be("alice");
        delivered.MessageId.Should().Be("m1");
        delivered.CreatedAt.Should().Be(CreatedAt);
        delivered.AdditionalProperties.Should().Contain("channel", "web");

        run.OutgoingEvents.OfType<WorkflowOutputEvent>().Should().ContainSingle()
            .Which.Data.Should().BeAssignableTo<List<ChatMessage>>()
            .Which.Single().Text.Should().Be($"my email is {Redacted}, photo attached");
    }

    [Fact]
    public async Task ShouldReplaceEarlierBlockedUserMessageWithPlaceholder_WhenListIsGuarded()
    {
        List<ChatMessage>? received = null;
        var inner = new VoidExecutor<List<ChatMessage>>("chat", message => received = message);
        var guarded = inner.WithGuardrails(PolicyWith(new BlockingRule("forbidden")));

        await guarded.HandleAsync(
        [
            new ChatMessage(ChatRole.User, "tell me the forbidden word") { MessageId = "u1" },
            new ChatMessage(ChatRole.Assistant, "I can't."),
            new ChatMessage(ChatRole.User, "what's the weather?")
        ], Mock.Of<IWorkflowContext>());

        received.Should().NotBeNull();
        var delivered = received!;
        delivered.Select(m => m.Text).Should().Equal(ChatMessageGuard.RemovedMessagePlaceholder, "I can't.", "what's the weather?");
        delivered[0].Role.Should().Be(ChatRole.User);
        delivered[0].MessageId.Should().Be("u1");
    }

    [Fact]
    public async Task ShouldThrow_WhenNewestUserMessageOfListIsBlocked()
    {
        var inner = new VoidExecutor<List<ChatMessage>>("chat", _ => { });
        var guarded = inner.WithGuardrails(PolicyWith(new BlockingRule("forbidden")));

        var act = () => guarded.HandleAsync(
            [new ChatMessage(ChatRole.User, "hello"), new ChatMessage(ChatRole.User, "now the forbidden word")],
            Mock.Of<IWorkflowContext>()).AsTask();

        var ex = await act.Should().ThrowAsync<GuardrailViolationException>();
        ex.Which.Phase.Should().Be(GuardrailPhase.Input);
        ex.Which.ExecutorId.Should().Be("chat");
        ex.Which.ViolationResult.Reason.Should().Be("mentions forbidden");
    }

    [Fact]
    public async Task ShouldRedactNewestMessage_WhenInputIsAnotherAgentsResponse()
    {
        List<ChatMessage>? received = null;
        var inner = new VoidExecutor<List<ChatMessage>>("reviewer", message => received = message);
        var guarded = inner.WithGuardrails(b => b.RedactPii());

        await guarded.HandleAsync(
            [new ChatMessage(ChatRole.Assistant, $"The customer writes from {Email}.") { AuthorName = "researcher" }],
            Mock.Of<IWorkflowContext>());

        var delivered = received.Should().ContainSingle().Subject;
        delivered.Text.Should().Be($"The customer writes from {Redacted}.");
        delivered.AuthorName.Should().Be("researcher");
    }

    [Fact]
    public async Task ShouldThrow_WhenNewestMessageOfInputIsAnotherAgentsBlockedResponse()
    {
        var inner = new VoidExecutor<List<ChatMessage>>("reviewer", _ => { });
        var guarded = inner.WithGuardrails(PolicyWith(new BlockingRule("forbidden")));

        var act = () => guarded.HandleAsync(
            [new ChatMessage(ChatRole.Assistant, "here is the forbidden word") { AuthorName = "researcher" }],
            Mock.Of<IWorkflowContext>()).AsTask();

        (await act.Should().ThrowAsync<GuardrailViolationException>()).Which.Phase.Should().Be(GuardrailPhase.Input);
    }

    [Fact]
    public async Task ShouldDeliverRedactedArray_WhenExecutorTakesChatMessageArray()
    {
        ChatMessage[]? received = null;
        var inner = new VoidExecutor<ChatMessage[]>("chat", message => received = message);
        var guarded = inner.WithGuardrails(b => b.RedactPii());

        await guarded.HandleAsync(
            [new ChatMessage(ChatRole.System, "be brief"), new ChatMessage(ChatRole.User, $"write to {Email}") { MessageId = "u1" }],
            Mock.Of<IWorkflowContext>());

        received.Should().NotBeNull();
        var delivered = received!;
        delivered.Select(m => m.Text).Should().Equal("be brief", $"write to {Redacted}");
        delivered[1].MessageId.Should().Be("u1");
    }

    [Fact]
    public async Task ShouldKeepAttachmentAndMetadata_WhenSingleChatMessageIsRewritten()
    {
        var photo = new DataContent(new byte[] { 1, 2, 3 }, "image/png");
        ChatMessage? received = null;
        var inner = new VoidExecutor<ChatMessage>("chat", message => received = message);
        var guarded = inner.WithGuardrails(b => b.RedactPii());

        await guarded.HandleAsync(
            new ChatMessage(ChatRole.User, [new TextContent($"my email is {Email}"), photo])
            {
                AuthorName = "alice",
                MessageId = "m1",
                CreatedAt = CreatedAt,
                AdditionalProperties = new() { ["channel"] = "web" }
            },
            Mock.Of<IWorkflowContext>());

        received.Should().NotBeNull();
        received!.Text.Should().Be($"my email is {Redacted}");
        received.Contents.OfType<DataContent>().Should().ContainSingle().Which.Should().BeSameAs(photo);
        received.AuthorName.Should().Be("alice");
        received.MessageId.Should().Be("m1");
        received.CreatedAt.Should().Be(CreatedAt);
        received.AdditionalProperties.Should().Contain("channel", "web");
    }

    [Fact]
    public async Task ShouldRedactAgentResponseAndKeepItsIdsAndUsage_WhenOutputIsRewritten()
    {
        var photo = new DataContent(new byte[] { 1, 2, 3 }, "image/png");
        var usage = new UsageDetails { InputTokenCount = 12, OutputTokenCount = 7, TotalTokenCount = 19 };
        var response = new AgentResponse(new ChatMessage(ChatRole.Assistant, [new TextContent($"Reach the rep at {Email}."), photo]) { MessageId = "a1" })
        {
            ResponseId = "resp-1",
            AgentId = "agent-1",
            CreatedAt = CreatedAt,
            Usage = usage,
            FinishReason = ChatFinishReason.Stop,
            AdditionalProperties = new() { ["trace"] = "t-1" }
        };
        var inner = new TypedExecutor<string, AgentResponse>("support", _ => response);
        var guarded = inner.WithGuardrails(b => b.RedactPii());

        var result = await guarded.HandleAsync("who is my rep?", Mock.Of<IWorkflowContext>());

        result.Should().NotBeSameAs(response);
        var message = result.Messages.Should().ContainSingle().Subject;
        message.Text.Should().Be($"Reach the rep at {Redacted}.");
        message.Contents.OfType<DataContent>().Should().ContainSingle().Which.Should().BeSameAs(photo);
        message.MessageId.Should().Be("a1");
        result.ResponseId.Should().Be("resp-1");
        result.AgentId.Should().Be("agent-1");
        result.CreatedAt.Should().Be(CreatedAt);
        result.Usage.Should().BeSameAs(usage);
        result.FinishReason.Should().Be(ChatFinishReason.Stop);
        result.AdditionalProperties.Should().Contain("trace", "t-1");
    }

    [Fact]
    public async Task ShouldThrowOnOutput_WhenAgentResponseIsBlocked()
    {
        var inner = new TypedExecutor<string, AgentResponse>(
            "support", _ => new AgentResponse(new ChatMessage(ChatRole.Assistant, "the forbidden answer")));
        var guarded = inner.WithGuardrails(PolicyWith(new BlockingRule("forbidden")));

        var act = () => guarded.HandleAsync("question", Mock.Of<IWorkflowContext>()).AsTask();

        var ex = await act.Should().ThrowAsync<GuardrailViolationException>();
        ex.Which.Phase.Should().Be(GuardrailPhase.Output);
        ex.Which.ExecutorId.Should().Be("support");
    }

    [Fact]
    public async Task ShouldReturnRedactedList_WhenOutputListIsRewritten()
    {
        var inner = new TypedExecutor<string, List<ChatMessage>>(
            "chat", _ => [new ChatMessage(ChatRole.Assistant, $"Write to {Email}.") { MessageId = "a1" }]);
        var guarded = inner.WithGuardrails(b => b.RedactPii());

        var result = await guarded.HandleAsync("how do I reach them?", Mock.Of<IWorkflowContext>());

        result.Should().BeOfType<List<ChatMessage>>();
        result.Single().Text.Should().Be($"Write to {Redacted}.");
        result.Single().MessageId.Should().Be("a1");
    }

    [Fact]
    public async Task ShouldRedactNewestOutputMessage_WhenItIsAPromptForTheNextAgent()
    {
        var inner = new TypedExecutor<string, List<ChatMessage>>(
            "prompt-builder", _ => [new ChatMessage(ChatRole.User, $"Draft a reply to {Email}")]);
        var guarded = inner.WithGuardrails(b => b.RedactPii());

        var result = await guarded.HandleAsync("draft it", Mock.Of<IWorkflowContext>());

        result.Single().Text.Should().Be($"Draft a reply to {Redacted}");
        result.Single().Role.Should().Be(ChatRole.User);
    }

    [Fact]
    public async Task ShouldPassOriginalAndLogWarning_WhenDeclaredCollectionTypeCannotBeRebuilt()
    {
        Collection<ChatMessage>? received = null;
        var logger = new ListLogger();
        var inner = new VoidExecutor<Collection<ChatMessage>>("chat", message => received = message);
        var guarded = inner.WithGuardrails(PolicyWith(new ReplacingRule("secret", "[redacted]")), new GuardedExecutorOptions { Logger = logger });

        var original = new Collection<ChatMessage> { new(ChatRole.User, "my secret expired") };
        await guarded.HandleAsync(original, Mock.Of<IWorkflowContext>());

        received.Should().BeSameAs(original);
        logger.Entries.Should().ContainSingle(e => e.Level == LogLevel.Warning)
            .Which.Message.Should().Contain("'chat'").And.Contain("could NOT be applied");
    }

    [Fact]
    public async Task ShouldNotConsultTextExtractor_WhenMessageIsChatPayload()
    {
        var extractor = new Mock<ITextExtractor>();
        List<ChatMessage>? received = null;
        var inner = new VoidExecutor<List<ChatMessage>>("chat", message => received = message);
        var guarded = inner.WithGuardrails(
            PolicyWith(new ReplacingRule("secret", "[redacted]")), new GuardedExecutorOptions { TextExtractor = extractor.Object });

        await guarded.HandleAsync([new ChatMessage(ChatRole.User, "my secret expired")], Mock.Of<IWorkflowContext>());

        received!.Single().Text.Should().Be("my [redacted] expired");
        extractor.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task ShouldRecordChatAndTextDecisionsInTheLedger_WhenBothAreGuarded()
    {
        var ledger = new RecordingLedger();
        var inner = new TypedExecutor<List<ChatMessage>, string>("chat", messages => $"echo: {messages[^1].Text}");
        var guarded = inner.WithGuardrails(
            PolicyWith(new ReplacingRule("secret", "[redacted]")), new GuardedExecutorOptions { Ledger = ledger });

        var result = await guarded.HandleAsync([new ChatMessage(ChatRole.User, "my secret expired")], Mock.Of<IWorkflowContext>());

        result.Should().Be("echo: my [redacted] expired");
        ledger.Decisions.Select(d => (d.Phase, d.WasModified)).Should().Equal((GuardrailPhase.Input, true), (GuardrailPhase.Output, false));
    }

    private static GuardrailPolicy PolicyWith(params IGuardrailRule[] rules) => new("test", rules);

    [YieldsOutput(typeof(List<ChatMessage>))]
    private sealed class ChatListExecutor(string id) : Executor<List<ChatMessage>>(id)
    {
        public List<List<ChatMessage>> Received { get; } = [];

        public override async ValueTask HandleAsync(List<ChatMessage> message, IWorkflowContext context, CancellationToken cancellationToken = default)
        {
            Received.Add(message);
            await context.YieldOutputAsync(message, cancellationToken);
        }
    }

    private sealed class VoidExecutor<T>(string id, Action<T> handle) : Executor<T>(id)
    {
        public override ValueTask HandleAsync(T message, IWorkflowContext context, CancellationToken cancellationToken = default)
        {
            handle(message);
            return ValueTask.CompletedTask;
        }
    }

    private sealed class TypedExecutor<TIn, TOut>(string id, Func<TIn, TOut> handle) : Executor<TIn, TOut>(id)
    {
        public override ValueTask<TOut> HandleAsync(TIn message, IWorkflowContext context, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(handle(message));
    }

    private sealed class BlockingRule(string word) : IGuardrailRule
    {
        public string Name => "block-word";
        public GuardrailPhase Phase => GuardrailPhase.Both;
        public int Order => 100;

        public ValueTask<GuardrailResult> EvaluateAsync(GuardrailContext context, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(context.Text.Contains(word, StringComparison.Ordinal)
                ? GuardrailResult.Blocked($"mentions {word}")
                : GuardrailResult.Passed());
    }

    private sealed class ReplacingRule(string find, string replacement) : IGuardrailRule
    {
        public string Name => "replace";
        public GuardrailPhase Phase => GuardrailPhase.Both;
        public int Order => 100;

        public ValueTask<GuardrailResult> EvaluateAsync(GuardrailContext context, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(context.Text.Contains(find, StringComparison.Ordinal)
                ? GuardrailResult.Modified(context.Text.Replace(find, replacement, StringComparison.Ordinal), $"replaced '{find}'")
                : GuardrailResult.Passed());
    }

    private sealed class RecordingLedger : IGuardrailLedger
    {
        public List<GuardrailDecision> Decisions { get; } = [];

        public void Append(GuardrailDecision decision) => Decisions.Add(decision);
    }

    private sealed class ListLogger : ILogger
    {
        public List<(LogLevel Level, string Message)> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            => Entries.Add((logLevel, formatter(state, exception)));
    }
}
