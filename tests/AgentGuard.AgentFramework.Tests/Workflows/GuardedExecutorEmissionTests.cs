using System.Diagnostics.CodeAnalysis;
using AgentGuard.AgentFramework.Workflows;
using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Guardrails;
using FluentAssertions;
using Microsoft.Agents.AI;
using Microsoft.Agents.AI.Workflows;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.Logging;
using Xunit;

namespace AgentGuard.AgentFramework.Workflows.Tests;

public class GuardedExecutorEmissionTests
{
    [Fact]
    public async Task VoidExecutor_ShouldThrowAndNotSend_WhenSentMessageIsBlocked()
    {
        var context = new RecordingContext();
        var guarded = Sending("relay", "the password is hunter2").WithGuardrails(PolicyWith(BlockingOutput("hunter2")));

        var act = () => guarded.HandleAsync("what is the password?", context).AsTask();

        var ex = await act.Should().ThrowAsync<GuardrailViolationException>();
        ex.Which.Phase.Should().Be(GuardrailPhase.Output);
        ex.Which.ExecutorId.Should().Be("relay");
        ex.Which.ViolationResult.Reason.Should().Be("contains hunter2");
        context.Sent.Should().BeEmpty();
    }

    [Fact]
    public async Task VoidExecutor_ShouldThrowAndNotYield_WhenYieldedOutputIsBlocked()
    {
        var context = new RecordingContext();
        var guarded = Yielding("relay", "the password is hunter2").WithGuardrails(PolicyWith(BlockingOutput("hunter2")));

        var act = () => guarded.HandleAsync("what is the password?", context).AsTask();

        var ex = await act.Should().ThrowAsync<GuardrailViolationException>();
        ex.Which.Phase.Should().Be(GuardrailPhase.Output);
        context.Yielded.Should().BeEmpty();
    }

    [Fact]
    public async Task VoidExecutor_ShouldSendRewrittenMessageToTheSameTarget_WhenSentMessageIsRewritten()
    {
        var context = new RecordingContext();
        var inner = new VoidExecutor<string>("relay", (_, ctx, ct) => ctx.SendMessageAsync("my secret plan", "desk", ct));
        var guarded = inner.WithGuardrails(PolicyWith(Redacting("secret")));

        await guarded.HandleAsync("go", context);

        var sent = context.Sent.Should().ContainSingle().Subject;
        sent.Message.Should().Be("my [redacted] plan");
        sent.TargetId.Should().Be("desk");
    }

    [Fact]
    public async Task VoidExecutor_ShouldYieldRewrittenOutput_WhenYieldedOutputIsRewritten()
    {
        var context = new RecordingContext();
        var guarded = Yielding("relay", "my secret plan").WithGuardrails(PolicyWith(Redacting("secret")));

        await guarded.HandleAsync("go", context);

        context.Yielded.Should().Equal("my [redacted] plan");
    }

    [Fact]
    public async Task VoidExecutor_ShouldPassSentAndYieldedMessagesThrough_WhenPolicyAllowsThem()
    {
        var context = new RecordingContext();
        var ticket = new Ticket("printer jammed");
        var inner = new VoidExecutor<string>("relay", async (_, ctx, ct) =>
        {
            await ctx.SendMessageAsync(ticket, targetId: null, ct);
            await ctx.YieldOutputAsync("filed", ct);
        });
        var guarded = inner.WithGuardrails(PolicyWith(BlockingOutput("hunter2")));

        await guarded.HandleAsync("go", context);

        context.Sent.Should().ContainSingle().Which.Message.Should().BeSameAs(ticket);
        context.Yielded.Should().Equal("filed");
    }

    [Fact]
    public async Task VoidExecutor_ShouldNotSend_WhenHandlerSwallowsTheViolation()
    {
        var context = new RecordingContext();
        var inner = new VoidExecutor<string>("relay", async (_, ctx, ct) =>
        {
            try
            {
                await ctx.SendMessageAsync("the password is hunter2", targetId: null, ct);
            }
            catch (GuardrailViolationException)
            {
                await ctx.SendMessageAsync("nothing to share", targetId: null, ct);
            }
        });
        var guarded = inner.WithGuardrails(PolicyWith(BlockingOutput("hunter2")));

        await guarded.HandleAsync("go", context);

        context.Sent.Select(s => s.Message).Should().Equal("nothing to share");
    }

    [Fact]
    public async Task VoidExecutor_ShouldEvaluateEmissionsWithOutputRulesOnly_WhenRuleIsInputOnly()
    {
        var context = new RecordingContext();
        var blockInput = new DelegateRule("block-input", GuardrailPhase.Input, c => c.Text.Contains("hunter2", StringComparison.Ordinal)
            ? GuardrailResult.Blocked("input rule")
            : GuardrailResult.Passed());
        var guarded = Sending("relay", "the password is hunter2").WithGuardrails(PolicyWith(blockInput));

        await guarded.HandleAsync("go", context);

        context.Sent.Select(s => s.Message).Should().Equal("the password is hunter2");
    }

    [Fact]
    public async Task TypedExecutor_ShouldThrowAndNotSend_WhenSentMessageIsBlocked()
    {
        var context = new RecordingContext();
        var inner = new TypedExecutor<string, string>("triage", async (_, ctx, ct) =>
        {
            await ctx.SendMessageAsync("the password is hunter2", targetId: null, ct);
            return "done";
        });
        var guarded = inner.WithGuardrails(PolicyWith(BlockingOutput("hunter2")));

        var act = () => guarded.HandleAsync("go", context).AsTask();

        var ex = await act.Should().ThrowAsync<GuardrailViolationException>();
        ex.Which.Phase.Should().Be(GuardrailPhase.Output);
        ex.Which.ExecutorId.Should().Be("triage");
        context.Sent.Should().BeEmpty();
    }

    [Fact]
    public async Task TypedExecutor_ShouldForwardRewrittenEmissionsAndResult_WhenAllAreRewritten()
    {
        var context = new RecordingContext();
        var inner = new TypedExecutor<string, string>("triage", async (_, ctx, ct) =>
        {
            await ctx.SendMessageAsync("sent secret", targetId: null, ct);
            await ctx.YieldOutputAsync("yielded secret", ct);
            return "returned secret";
        });
        var guarded = inner.WithGuardrails(PolicyWith(Redacting("secret")));

        var result = await guarded.HandleAsync("go", context);

        context.Sent.Select(s => s.Message).Should().Equal("sent [redacted]");
        context.Yielded.Should().Equal("yielded [redacted]");
        result.Should().Be("returned [redacted]");
    }

    [Fact]
    public async Task ShouldRewriteChatMessageTextAndKeepItsMetadata_WhenSentChatMessageIsRewritten()
    {
        var context = new RecordingContext();
        var message = new ChatMessage(ChatRole.Assistant, "my secret plan") { AuthorName = "planner", MessageId = "m-1" };
        var inner = new VoidExecutor<string>("relay", (_, ctx, ct) => ctx.SendMessageAsync(message, targetId: null, ct));
        var guarded = inner.WithGuardrails(PolicyWith(Redacting("secret")));

        await guarded.HandleAsync("go", context);

        var sent = context.Sent.Should().ContainSingle().Which.Message.Should().BeOfType<ChatMessage>().Subject;
        sent.Text.Should().Be("my [redacted] plan");
        sent.Role.Should().Be(ChatRole.Assistant);
        sent.AuthorName.Should().Be("planner");
        sent.MessageId.Should().Be("m-1");
    }

    [Fact]
    public async Task ShouldGuardYieldedAgentResponseLikeAResponse_WhenAssistantMessageIsRewritten()
    {
        var context = new RecordingContext();
        var response = new AgentResponse([new ChatMessage(ChatRole.Assistant, "the secret is out")]) { ResponseId = "r-1" };
        var inner = new VoidExecutor<string>("relay", (_, ctx, ct) => ctx.YieldOutputAsync(response, ct));
        var guarded = inner.WithGuardrails(PolicyWith(Redacting("secret")));

        await guarded.HandleAsync("go", context);

        var yielded = context.Yielded.Should().ContainSingle().Which.Should().BeOfType<AgentResponse>().Subject;
        yielded.Text.Should().Be("the [redacted] is out");
        yielded.ResponseId.Should().Be("r-1");
    }

    [Fact]
    public async Task ShouldThrowAndNotSend_WhenSentChatMessageListIsBlocked()
    {
        var context = new RecordingContext();
        List<ChatMessage> messages = [new(ChatRole.Assistant, "the password is hunter2")];
        var inner = new VoidExecutor<string>("relay", (_, ctx, ct) => ctx.SendMessageAsync(messages, targetId: null, ct));
        var guarded = inner.WithGuardrails(PolicyWith(BlockingOutput("hunter2")));

        var act = () => guarded.HandleAsync("go", context).AsTask();

        await act.Should().ThrowAsync<GuardrailViolationException>();
        context.Sent.Should().BeEmpty();
    }

    [Fact]
    public async Task ShouldSendRebuiltMessage_WhenExtractorRebuildsRewrittenType()
    {
        var context = new RecordingContext();
        var inner = new VoidExecutor<string>("relay", (_, ctx, ct) => ctx.SendMessageAsync(new Ticket("my secret expired"), targetId: null, ct));
        var guarded = inner.WithGuardrails(
            PolicyWith(Redacting("secret")),
            new GuardedExecutorOptions { TextExtractor = new TicketTextExtractor() });

        await guarded.HandleAsync("go", context);

        context.Sent.Select(s => s.Message).Should().Equal(new Ticket("my [redacted] expired"));
    }

    [Fact]
    public async Task ShouldSendRebuiltMessage_WhenDefaultExtractorRebuildsRecordWithText()
    {
        var context = new RecordingContext();
        var note = new Note("my secret plan", Pinned: true);
        var inner = new VoidExecutor<string>("relay", (_, ctx, ct) => ctx.SendMessageAsync(note, targetId: null, ct));
        var guarded = inner.WithGuardrails(PolicyWith(Redacting("secret")));

        await guarded.HandleAsync("go", context);

        context.Sent.Select(s => s.Message).Should().Equal(new Note("my [redacted] plan", Pinned: true));
        note.Text.Should().Be("my secret plan");
    }

    [Fact]
    public async Task ShouldBlockAndLogWarning_WhenRewrittenSentMessageCannotBeRebuilt()
    {
        var context = new RecordingContext();
        var logger = new ListLogger();
        var inner = new VoidExecutor<string>("relay", (_, ctx, ct) => ctx.SendMessageAsync(new Ticket("my secret expired"), targetId: null, ct));
        var guarded = inner.WithGuardrails(PolicyWith(Redacting("secret")), new GuardedExecutorOptions { Logger = logger });

        var act = () => guarded.HandleAsync("go", context).AsTask();

        var ex = await act.Should().ThrowAsync<GuardrailViolationException>();
        ex.Which.Phase.Should().Be(GuardrailPhase.Output);
        ex.Which.ExecutorId.Should().Be("relay");
        ex.Which.ViolationResult.Reason.Should().Contain(nameof(Ticket)).And.Contain("AllowUnappliedModifications");
        context.Sent.Should().BeEmpty();
        logger.Entries.Should().ContainSingle(e => e.Level == LogLevel.Warning)
            .Which.Message.Should().Contain("'relay'").And.Contain(nameof(Ticket)).And.Contain("was blocked");
    }

    [Fact]
    public async Task ShouldBlock_WhenRewrittenYieldedOutputCannotBeRebuilt()
    {
        var context = new RecordingContext();
        var guarded = Yielding("relay", new Ticket("my secret expired")).WithGuardrails(PolicyWith(Redacting("secret")));

        var act = () => guarded.HandleAsync("go", context).AsTask();

        var ex = await act.Should().ThrowAsync<GuardrailViolationException>();
        ex.Which.Phase.Should().Be(GuardrailPhase.Output);
        context.Yielded.Should().BeEmpty();
    }

    [Fact]
    public async Task ShouldSendOriginalAndLogWarning_WhenRewrittenSentMessageCannotBeRebuiltAndUnappliedModificationsAreAllowed()
    {
        var context = new RecordingContext();
        var logger = new ListLogger();
        var ticket = new Ticket("my secret expired");
        var inner = new VoidExecutor<string>("relay", (_, ctx, ct) => ctx.SendMessageAsync(ticket, targetId: null, ct));
        var guarded = inner.WithGuardrails(
            PolicyWith(Redacting("secret")),
            new GuardedExecutorOptions { Logger = logger, AllowUnappliedModifications = true });

        await guarded.HandleAsync("go", context);

        context.Sent.Should().ContainSingle().Which.Message.Should().BeSameAs(ticket);
        logger.Entries.Should().ContainSingle(e => e.Level == LogLevel.Warning)
            .Which.Message.Should().Contain("'relay'").And.Contain(nameof(Ticket)).And.Contain("could NOT be applied");
    }

    [Fact]
    public async Task ShouldBlock_WhenRebuiltMessageIsNotTheSentType()
    {
        var context = new RecordingContext();
        var inner = new VoidExecutor<string>("relay", (_, ctx, ct) => ctx.SendMessageAsync(new Ticket("my secret expired"), targetId: null, ct));
        var guarded = inner.WithGuardrails(
            PolicyWith(Redacting("secret")),
            new GuardedExecutorOptions { TextExtractor = new TextOnlyExtractor() });

        var act = () => guarded.HandleAsync("go", context).AsTask();

        var ex = await act.Should().ThrowAsync<GuardrailViolationException>();
        ex.Which.Phase.Should().Be(GuardrailPhase.Output);
        context.Sent.Should().BeEmpty();
    }

    [Fact]
    public async Task ShouldSendOriginal_WhenRebuiltMessageIsNotTheSentTypeAndUnappliedModificationsAreAllowed()
    {
        var context = new RecordingContext();
        var logger = new ListLogger();
        var ticket = new Ticket("my secret expired");
        var inner = new VoidExecutor<string>("relay", (_, ctx, ct) => ctx.SendMessageAsync(ticket, targetId: null, ct));
        var guarded = inner.WithGuardrails(
            PolicyWith(Redacting("secret")),
            new GuardedExecutorOptions { TextExtractor = new TextOnlyExtractor(), Logger = logger, AllowUnappliedModifications = true });

        await guarded.HandleAsync("go", context);

        context.Sent.Should().ContainSingle().Which.Message.Should().BeSameAs(ticket);
        logger.Entries.Should().ContainSingle(e => e.Level == LogLevel.Warning);
    }

    [Fact]
    public async Task ShouldSendWithoutEvaluating_WhenMessageCarriesNoText()
    {
        var context = new RecordingContext();
        var evaluated = new List<string>();
        var token = new TurnToken(emitEvents: false);
        var inner = new VoidExecutor<string>("relay", async (_, ctx, ct) =>
        {
            await ctx.SendMessageAsync(token, targetId: null, ct);
            await ctx.YieldOutputAsync(string.Empty, ct);
        });
        var guarded = inner.WithGuardrails(PolicyWith(Recording(GuardrailPhase.Output, evaluated)));

        await guarded.HandleAsync("go", context);

        context.Sent.Should().ContainSingle().Which.Message.Should().BeSameAs(token);
        context.Yielded.Should().Equal(string.Empty);
        evaluated.Should().BeEmpty();
    }

    [Fact]
    public async Task ShouldGuardWhatAPortableValueCarries_WhenExecutorRelaysOne()
    {
        var context = new RecordingContext();
        var inner = new VoidExecutor<string>("relay", (_, ctx, ct) => ctx.SendMessageAsync(new PortableValue("my secret plan"), targetId: null, ct));
        var guarded = inner.WithGuardrails(PolicyWith(Redacting("secret")));

        await guarded.HandleAsync("go", context);

        context.Sent.Should().ContainSingle().Which.Message.Should().BeOfType<PortableValue>()
            .Which.As<string>().Should().Be("my [redacted] plan");
    }

    [Fact]
    public async Task ShouldLeaveEventsUnguarded_WhenExecutorAddsAnEvent()
    {
        var context = new RecordingContext();
        var workflowEvent = new WorkflowEvent("the password is hunter2");
        var inner = new VoidExecutor<string>("relay", (_, ctx, ct) => ctx.AddEventAsync(workflowEvent, ct));
        var guarded = inner.WithGuardrails(PolicyWith(BlockingOutput("hunter2")));

        await guarded.HandleAsync("go", context);

        context.Events.Should().ContainSingle().Which.Should().BeSameAs(workflowEvent);
    }

    [Fact]
    public async Task ShouldDelegateStateHaltAndContextProperties_WhenExecutorUsesThem()
    {
        var context = new RecordingContext();
        IReadOnlyDictionary<string, string>? traceContext = null;
        var concurrentRuns = false;
        using var cancellation = new CancellationTokenSource();
        var inner = new VoidExecutor<string>("relay", async (_, ctx, ct) =>
        {
            traceContext = ctx.TraceContext;
            concurrentRuns = ctx.ConcurrentRunsEnabled;
            await ctx.QueueStateUpdateAsync("count", 1, ct);
            await ctx.QueueStateUpdateAsync("count", 2, "scope", ct);
            await ctx.ReadStateAsync<int>("count", ct);
            await ctx.ReadStateAsync<int>("count", "scope", ct);
            await ctx.ReadOrInitStateAsync("count", () => 3, ct);
            await ctx.ReadOrInitStateAsync("count", () => 4, "scope", ct);
            await ctx.ReadStateKeysAsync("scope", ct);
            await ctx.QueueClearScopeAsync(ct);
            await ctx.QueueClearScopeAsync("scope", ct);
            await ctx.RequestHaltAsync();
        });
        var guarded = inner.WithGuardrails(PolicyWith(BlockingOutput("hunter2")));

        await guarded.HandleAsync("go", context, cancellation.Token);

        traceContext.Should().BeSameAs(context.TraceContext);
        concurrentRuns.Should().BeTrue();
        context.Calls.Should().Equal(
            "QueueStateUpdate(count, 1) in default scope",
            "QueueStateUpdate(count, 2, scope)",
            "ReadState(count) in default scope",
            "ReadState(count, scope)",
            "ReadOrInitState(count, 3) in default scope",
            "ReadOrInitState(count, 4, scope)",
            "ReadStateKeys(scope)",
            "QueueClearScope() in default scope",
            "QueueClearScope(scope)",
            "RequestHalt");
        context.CancellationTokens.Should().OnlyContain(token => token == cancellation.Token);
    }

    [Fact]
    public async Task ShouldDeliverRewrittenMessageAndOutput_WhenWorkflowExecutorEmitsThem()
    {
        var relay = new RelayExecutor("relay", message => $"my secret {message}");
        var sink = new SinkExecutor("sink");
        var guarded = relay.WithGuardrails(PolicyWith(Redacting("secret")));
        var workflow = new WorkflowBuilder(guarded).AddEdge(guarded, sink).WithOutputFrom(guarded).Build();

        await using var run = await InProcessExecution.RunAsync(workflow, "plan");

        Failures(run).Should().BeEmpty();
        sink.Received.Should().Equal("my [redacted] plan");
        Outputs(run).Should().Equal("my [redacted] plan");
    }

    [Fact]
    public async Task ShouldNotDeliverMessageAndFailExecutor_WhenWorkflowExecutorSendsBlockedMessage()
    {
        var relay = new RelayExecutor("relay", _ => "the password is hunter2");
        var sink = new SinkExecutor("sink");
        var guarded = relay.WithGuardrails(PolicyWith(BlockingOutput("hunter2")));
        var workflow = new WorkflowBuilder(guarded).AddEdge(guarded, sink).WithOutputFrom(guarded).Build();

        await using var run = await InProcessExecution.RunAsync(workflow, "what is the password?");

        sink.Received.Should().BeEmpty();
        Outputs(run).Should().BeEmpty();
        var violation = run.OutgoingEvents.OfType<ExecutorFailedEvent>().Should().ContainSingle()
            .Which.Data.Should().BeOfType<GuardrailViolationException>().Subject;
        violation.Phase.Should().Be(GuardrailPhase.Output);
        violation.ExecutorId.Should().Be("relay");
    }

    [Fact]
    public async Task ShouldGuardReturnedValueOnce_WhenFrameworkSendsAndYieldsIt()
    {
        var evaluated = new List<string>();
        var inner = new TypedExecutor<string, string>("triage", (message, _, _) => ValueTask.FromResult($"triaged: {message}"));
        var sink = new SinkExecutor("sink");
        var guarded = inner.WithGuardrails(PolicyWith(Recording(GuardrailPhase.Output, evaluated)));
        var workflow = new WorkflowBuilder(guarded).AddEdge(guarded, sink).WithOutputFrom(guarded).Build();

        await using var run = await InProcessExecution.RunAsync(workflow, "printer");

        Failures(run).Should().BeEmpty();
        sink.Received.Should().Equal("triaged: printer");
        Outputs(run).Should().Equal("triaged: printer");
        evaluated.Should().Equal("triaged: printer");
    }

    [Fact]
    public async Task ShouldGuardOtherHandlersResultOnce_WhenFrameworkSendsAndYieldsIt()
    {
        var evaluated = new List<string>();
        var inner = new TicketAnsweringExecutor("answers");
        var sink = new SinkExecutor("sink");
        var guarded = inner.WithGuardrails(PolicyWith(Recording(GuardrailPhase.Output, evaluated), Redacting("secret", GuardrailPhase.Output)));
        var workflow = new WorkflowBuilder(guarded).AddEdge(guarded, sink).WithOutputFrom(guarded).Build();

        await using var run = await InProcessExecution.RunAsync(workflow, new Ticket("the secret door"));

        Failures(run).Should().BeEmpty();
        sink.Received.Should().Equal("answer: the [redacted] door");
        Outputs(run).Should().Equal("answer: the [redacted] door");
        evaluated.Should().Equal("answer: the secret door");
    }

    [Fact]
    public async Task ShouldReportOtherHandlersResultAsGuarded_WhenInnerExecutorRaisesItsCompletedEvent()
    {
        var inner = new TicketAnsweringExecutor("answers");
        var guarded = inner.WithGuardrails(PolicyWith(Redacting("secret", GuardrailPhase.Output)));
        var workflow = new WorkflowBuilder(guarded).WithOutputFrom(guarded).Build();

        await using var run = await InProcessExecution.RunAsync(workflow, new Ticket("the secret door"));

        Failures(run).Should().BeEmpty();
        run.OutgoingEvents.OfType<ExecutorCompletedEvent>().Should().ContainSingle(e => e.ExecutorId == "answers")
            .Which.Data.Should().Be("answer: the [redacted] door");
    }

    [Fact]
    public async Task ShouldNotDeliverOtherHandlersResult_WhenItIsBlocked()
    {
        var inner = new TicketAnsweringExecutor("answers");
        var sink = new SinkExecutor("sink");
        var guarded = inner.WithGuardrails(PolicyWith(BlockingOutput("door")));
        var workflow = new WorkflowBuilder(guarded).AddEdge(guarded, sink).WithOutputFrom(guarded).Build();

        await using var run = await InProcessExecution.RunAsync(workflow, new Ticket("the secret door"));

        sink.Received.Should().BeEmpty();
        Outputs(run).Should().BeEmpty();
        run.OutgoingEvents.OfType<ExecutorCompletedEvent>().Should().NotContain(e => e.ExecutorId == "answers");
        run.OutgoingEvents.OfType<ExecutorFailedEvent>().Should().Contain(e => e.ExecutorId == "guarded-answers")
            .Which.Data.Should().BeOfType<GuardrailViolationException>()
            .Which.Phase.Should().Be(GuardrailPhase.Output);
    }

    [Fact]
    public async Task ShouldGuardMessagesSentFromLifecycleHooks_WhenExecutorFlushesAfterDelivery()
    {
        var inner = new BatchingExecutor("batch");
        var sink = new SinkExecutor("sink");
        var guarded = inner.WithGuardrails(PolicyWith(Redacting("secret")));
        var workflow = new WorkflowBuilder(guarded).AddEdge(guarded, sink).Build();

        await using var run = await InProcessExecution.RunAsync(workflow, "plan");

        Failures(run).Should().BeEmpty();
        sink.Received.Should().Equal("batched [redacted] plan");
    }

    private static GuardrailPolicy PolicyWith(params IGuardrailRule[] rules) => new("test", rules);

    private static VoidExecutor<string> Sending(string id, object message) =>
        new(id, (_, context, cancellationToken) => context.SendMessageAsync(message, targetId: null, cancellationToken));

    private static VoidExecutor<string> Yielding(string id, object output) =>
        new(id, (_, context, cancellationToken) => context.YieldOutputAsync(output, cancellationToken));

    private static DelegateRule BlockingOutput(string word) =>
        new("block", GuardrailPhase.Output, context => context.Text.Contains(word, StringComparison.Ordinal)
            ? GuardrailResult.Blocked($"contains {word}")
            : GuardrailResult.Passed());

    private static DelegateRule Redacting(string word, GuardrailPhase phase = GuardrailPhase.Both) =>
        new("redact", phase, context => context.Text.Contains(word, StringComparison.Ordinal)
            ? GuardrailResult.Modified(context.Text.Replace(word, "[redacted]", StringComparison.Ordinal), $"redacted '{word}'")
            : GuardrailResult.Passed());

    private static DelegateRule Recording(GuardrailPhase phase, List<string> evaluated) =>
        new("record", phase, context =>
        {
            evaluated.Add(context.Text);
            return GuardrailResult.Passed();
        }, order: 50);

    private static IEnumerable<WorkflowEvent> Failures(Run run) =>
        run.OutgoingEvents.Where(e => e is WorkflowErrorEvent or ExecutorFailedEvent);

    private static IEnumerable<object?> Outputs(Run run) =>
        run.OutgoingEvents.OfType<WorkflowOutputEvent>().Select(e => e.Data);

    private sealed record Ticket(string Body);

    private sealed record Note(string Text, bool Pinned);

    private sealed class VoidExecutor<T>(string id, Func<T, IWorkflowContext, CancellationToken, ValueTask> handle) : Executor<T>(id)
    {
        public override ValueTask HandleAsync(T message, IWorkflowContext context, CancellationToken cancellationToken = default) =>
            handle(message, context, cancellationToken);
    }

    private sealed class TypedExecutor<TIn, TOut>(string id, Func<TIn, IWorkflowContext, CancellationToken, ValueTask<TOut>> handle)
        : Executor<TIn, TOut>(id)
    {
        public override ValueTask<TOut> HandleAsync(TIn message, IWorkflowContext context, CancellationToken cancellationToken = default) =>
            handle(message, context, cancellationToken);
    }

    [SendsMessage(typeof(string))]
    [YieldsOutput(typeof(string))]
    private sealed class RelayExecutor(string id, Func<string, string> compose) : Executor<string>(id)
    {
        public override async ValueTask HandleAsync(string message, IWorkflowContext context, CancellationToken cancellationToken = default)
        {
            var composed = compose(message);
            await context.SendMessageAsync(composed, targetId: null, cancellationToken);
            await context.YieldOutputAsync(composed, cancellationToken);
        }
    }

    private sealed class SinkExecutor(string id) : Executor<string>(id)
    {
        public List<string> Received { get; } = [];

        public override ValueTask HandleAsync(string message, IWorkflowContext context, CancellationToken cancellationToken = default)
        {
            Received.Add(message);
            return ValueTask.CompletedTask;
        }
    }

    // handles tickets through a second route whose result the framework sends and yields
    private sealed class TicketAnsweringExecutor(string id) : Executor<string>(id)
    {
        protected override ProtocolBuilder ConfigureProtocol(ProtocolBuilder protocolBuilder)
        {
            Func<Ticket, IWorkflowContext, CancellationToken, ValueTask<string>> answer = AnswerAsync;
            return base.ConfigureProtocol(protocolBuilder).ConfigureRoutes(routes => routes.AddHandler(answer));
        }

        public override ValueTask HandleAsync(string message, IWorkflowContext context, CancellationToken cancellationToken = default) =>
            ValueTask.CompletedTask;

        private static ValueTask<string> AnswerAsync(Ticket ticket, IWorkflowContext context, CancellationToken cancellationToken) =>
            ValueTask.FromResult($"answer: {ticket.Body}");
    }

    [SendsMessage(typeof(string))]
    private sealed class BatchingExecutor(string id) : Executor<string>(id)
    {
        private readonly List<string> _pending = [];

        public override ValueTask HandleAsync(string message, IWorkflowContext context, CancellationToken cancellationToken = default)
        {
            _pending.Add(message);
            return ValueTask.CompletedTask;
        }

        protected override async ValueTask OnMessageDeliveryFinishedAsync(IWorkflowContext context, CancellationToken cancellationToken = default)
        {
            foreach (var message in _pending)
                await context.SendMessageAsync($"batched secret {message}", targetId: null, cancellationToken);

            _pending.Clear();
        }
    }

    private sealed class TicketTextExtractor : ITextExtractor
    {
        public string? ExtractText(object? message) =>
            message is Ticket ticket ? ticket.Body : DefaultTextExtractor.Instance.ExtractText(message);

        public bool TryRebuild(object message, string text, [NotNullWhen(true)] out object? rebuilt)
        {
            rebuilt = message is Ticket ticket ? ticket with { Body = text } : null;
            return rebuilt is not null;
        }
    }

    // rebuilds every message as plain text, whatever type was sent
    private sealed class TextOnlyExtractor : ITextExtractor
    {
        public string? ExtractText(object? message) =>
            message is Ticket ticket ? ticket.Body : DefaultTextExtractor.Instance.ExtractText(message);

        public bool TryRebuild(object message, string text, [NotNullWhen(true)] out object? rebuilt)
        {
            rebuilt = text;
            return true;
        }
    }

    private sealed class DelegateRule(string name, GuardrailPhase phase, Func<GuardrailContext, GuardrailResult> evaluate, int order = 100)
        : IGuardrailRule
    {
        public string Name => name;
        public GuardrailPhase Phase => phase;
        public int Order => order;

        public ValueTask<GuardrailResult> EvaluateAsync(GuardrailContext context, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(evaluate(context));
    }

    private sealed class ListLogger : ILogger
    {
        public List<(LogLevel Level, string Message)> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            => Entries.Add((logLevel, formatter(state, exception)));
    }

    // records what reaches the workflow runtime; the overloads without a scope name are recorded apart from
    // the scoped ones, since a context may implement them differently
    private sealed class RecordingContext : IWorkflowContext
    {
        public List<(object Message, string? TargetId)> Sent { get; } = [];

        public List<object> Yielded { get; } = [];

        public List<WorkflowEvent> Events { get; } = [];

        public List<string> Calls { get; } = [];

        public List<CancellationToken> CancellationTokens { get; } = [];

        public IReadOnlyDictionary<string, string>? TraceContext { get; } = new Dictionary<string, string> { ["traceparent"] = "00-trace" };

        public bool ConcurrentRunsEnabled => true;

        public ValueTask AddEventAsync(WorkflowEvent workflowEvent, CancellationToken cancellationToken = default)
        {
            Events.Add(workflowEvent);
            return ValueTask.CompletedTask;
        }

        public ValueTask SendMessageAsync(object message, string? targetId, CancellationToken cancellationToken = default)
        {
            Sent.Add((message, targetId));
            return ValueTask.CompletedTask;
        }

        public ValueTask YieldOutputAsync(object output, CancellationToken cancellationToken = default)
        {
            Yielded.Add(output);
            return ValueTask.CompletedTask;
        }

        public ValueTask RequestHaltAsync()
        {
            Calls.Add("RequestHalt");
            return ValueTask.CompletedTask;
        }

        public ValueTask<T?> ReadStateAsync<T>(string key, string? scopeName = null, CancellationToken cancellationToken = default) =>
            Record<T?>($"ReadState({key}, {scopeName})", cancellationToken);

        public ValueTask<T?> ReadStateAsync<T>(string key, CancellationToken cancellationToken) =>
            Record<T?>($"ReadState({key}) in default scope", cancellationToken);

        public ValueTask<T> ReadOrInitStateAsync<T>(string key, Func<T> initialStateFactory, string? scopeName = null, CancellationToken cancellationToken = default) =>
            Record($"ReadOrInitState({key}, {initialStateFactory()}, {scopeName})", cancellationToken, initialStateFactory());

        public ValueTask<T> ReadOrInitStateAsync<T>(string key, Func<T> initialStateFactory, CancellationToken cancellationToken) =>
            Record($"ReadOrInitState({key}, {initialStateFactory()}) in default scope", cancellationToken, initialStateFactory());

        public ValueTask<HashSet<string>> ReadStateKeysAsync(string? scopeName = null, CancellationToken cancellationToken = default) =>
            Record($"ReadStateKeys({scopeName})", cancellationToken, new HashSet<string>());

        public async ValueTask QueueStateUpdateAsync<T>(string key, T? value, string? scopeName = null, CancellationToken cancellationToken = default) =>
            await Record<object?>($"QueueStateUpdate({key}, {value}, {scopeName})", cancellationToken);

        public async ValueTask QueueStateUpdateAsync<T>(string key, T? value, CancellationToken cancellationToken) =>
            await Record<object?>($"QueueStateUpdate({key}, {value}) in default scope", cancellationToken);

        public async ValueTask QueueClearScopeAsync(string? scopeName = null, CancellationToken cancellationToken = default) =>
            await Record<object?>($"QueueClearScope({scopeName})", cancellationToken);

        public async ValueTask QueueClearScopeAsync(CancellationToken cancellationToken) =>
            await Record<object?>("QueueClearScope() in default scope", cancellationToken);

        private ValueTask<T> Record<T>(string call, CancellationToken cancellationToken, T result = default!)
        {
            Calls.Add(call);
            CancellationTokens.Add(cancellationToken);
            return ValueTask.FromResult(result);
        }
    }
}
