using System.Diagnostics.CodeAnalysis;
using AgentGuard.AgentFramework.Workflows;
using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Guardrails;
using FluentAssertions;
using Microsoft.Agents.AI.Workflows;
using Microsoft.Extensions.AI;
using Xunit;

namespace AgentGuard.AgentFramework.Workflows.Tests;

public class GuardedExecutorWorkflowTests
{
    [Fact]
    public async Task ShouldDeliverSentMessagesAndYieldedOutput_WhenVoidInnerExecutorSendsOtherTypes()
    {
        var intake = new TicketIntakeExecutor("intake");
        var desk = new TicketDeskExecutor("desk");
        var guarded = intake.WithGuardrails(Redacting("secret"));

        var workflow = new WorkflowBuilder(guarded)
            .AddEdge(guarded, desk)
            .WithOutputFrom(guarded, desk)
            .Build();

        await using var run = await InProcessExecution.RunAsync(workflow, "my secret password expired");

        Failures(run).Should().BeEmpty();
        desk.Received.Should().Equal(new Ticket("my [redacted] password expired"));
        Outputs(run).Should().Contain(new TicketSummary("filed: my [redacted] password expired"))
            .And.Contain("desk: my [redacted] password expired");
    }

    [Fact]
    public async Task ShouldDeliverSentMessagesAndResult_WhenTypedInnerExecutorSendsOtherTypes()
    {
        var triage = new TriageExecutor("triage");
        var desk = new TicketDeskExecutor("desk");
        var guarded = triage.WithGuardrails(Redacting("secret"));

        var workflow = new WorkflowBuilder(guarded)
            .AddEdge(guarded, desk)
            .WithOutputFrom(guarded, desk)
            .Build();

        await using var run = await InProcessExecution.RunAsync(workflow, "my secret expired");

        Failures(run).Should().BeEmpty();
        desk.Received.Should().Equal(new Ticket("my [redacted] expired"));
        Outputs(run).Should().Contain("triaged: my [redacted] expired")
            .And.Contain("desk: my [redacted] expired");
    }

    [Fact]
    public void ShouldDescribeInnerProtocol_WhenWrapped()
    {
        var inner = new MultiInputExecutor("multi");
        var guarded = inner.WithGuardrails(PolicyWith());

        var expected = inner.DescribeProtocol();
        var actual = guarded.DescribeProtocol();

        actual.Accepts.Should().BeEquivalentTo(expected.Accepts);
        actual.Sends.Should().BeEquivalentTo(expected.Sends);
        actual.Yields.Should().BeEquivalentTo(expected.Yields);
        actual.AcceptsAll.Should().Be(expected.AcceptsAll);
    }

    [Fact]
    public async Task ShouldForwardOtherHandledTypes_WhenInnerExecutorHandlesMoreThanItsInputType()
    {
        var inner = new MultiInputExecutor("multi");
        var workflow = new WorkflowBuilder(inner.WithGuardrails(Redacting("secret"))).Build();

        await using var run = await InProcessExecution.RunAsync(workflow, new Ticket("printer jammed"));

        Failures(run).Should().BeEmpty();
        inner.Received.Should().Equal(new Ticket("printer jammed"));
    }

    [Fact]
    public async Task ShouldForwardRebuiltMessage_WhenOtherHandledTypeIsRewritten()
    {
        var inner = new MultiInputExecutor("multi");
        var guarded = inner.WithGuardrails(Redacting("secret"), new GuardedExecutorOptions { TextExtractor = new TicketTextExtractor() });
        var workflow = new WorkflowBuilder(guarded).Build();

        await using var run = await InProcessExecution.RunAsync(workflow, new Ticket("my secret expired"));

        Failures(run).Should().BeEmpty();
        inner.Received.Should().Equal(new Ticket("my [redacted] expired"));
    }

    [Fact]
    public async Task ShouldForwardToInnerCatchAll_WhenInnerExecutorAcceptsAnyMessage()
    {
        var inner = new CatchAllExecutor("catch-all");
        var guarded = inner.WithGuardrails(Redacting("secret"));

        guarded.DescribeProtocol().AcceptsAll.Should().BeTrue();

        var workflow = new WorkflowBuilder(guarded).Build();
        await using var run = await InProcessExecution.RunAsync(workflow, new Ticket("printer jammed"));

        Failures(run).Should().BeEmpty();
        inner.Caught.Should().Equal(new Ticket("printer jammed"));
    }

    [Fact]
    public async Task ShouldKeepChatProtocolAndForwardTurnTokenUnchecked_WhenInnerExecutorTakesTurns()
    {
        var inner = new ChatTurnExecutor("chat");
        var evaluated = new List<string>();
        var guarded = inner.WithGuardrails(PolicyWith(new RecordingRule(evaluated)));

        guarded.DescribeProtocol().IsChatProtocol().Should().BeTrue();

        var workflow = new WorkflowBuilder(guarded).Build();
        await using var run = await InProcessExecution.RunAsync(workflow, new TurnToken(emitEvents: false));

        Failures(run).Should().BeEmpty();
        inner.Turns.Should().Be(1);
        evaluated.Should().BeEmpty();
    }

    [Fact]
    public async Task ShouldNotForwardOtherHandledType_WhenItsInputIsBlocked()
    {
        var inner = new MultiInputExecutor("multi");
        var workflow = new WorkflowBuilder(inner.WithGuardrails(PolicyWith(new BlockingRule("no tickets")))).Build();

        await using var run = await InProcessExecution.RunAsync(workflow, new Ticket("printer jammed"));

        inner.Received.Should().BeEmpty();
        run.OutgoingEvents.OfType<ExecutorFailedEvent>().Should().ContainSingle()
            .Which.Data.Should().BeOfType<GuardrailViolationException>()
            .Which.ViolationResult.Reason.Should().Be("no tickets");
    }

    [Fact]
    public async Task ShouldForwardLifecycleHooks_WhenWorkflowRunsWithCheckpointing()
    {
        var inner = new CountingExecutor("counter");
        var workflow = new WorkflowBuilder(inner.WithGuardrails(PolicyWith())).Build();

        await using var run = await InProcessExecution.RunAsync(workflow, "first", CheckpointManager.CreateInMemory());

        inner.Count.Should().Be(1);
        inner.Calls.Should().Equal("initialize", "delivery-starting", "delivery-finished", "checkpointing");
    }

    [Fact]
    public async Task ShouldRestoreInnerExecutorState_WhenCheckpointIsRestored()
    {
        var inner = new CountingExecutor("counter");
        var workflow = new WorkflowBuilder(inner.WithGuardrails(PolicyWith())).Build();

        await using var run = await InProcessExecution.RunAsync(workflow, "first", CheckpointManager.CreateInMemory());
        var checkpoint = run.LastCheckpoint;
        inner.Count = 42;

        checkpoint.Should().NotBeNull();
        await run.RestoreCheckpointAsync(checkpoint!);

        inner.Count.Should().Be(1);
        inner.Calls.Should().EndWith("restored");
    }

    [Fact]
    public async Task ShouldResetInnerExecutor_WhenWorkflowRunEnds()
    {
        var inner = new ResettableExecutor("resettable");
        var guarded = inner.WithGuardrails(PolicyWith());
        var workflow = new WorkflowBuilder(guarded).Build();

        await (await InProcessExecution.RunAsync(workflow, "first")).DisposeAsync();
        await (await InProcessExecution.RunAsync(workflow, "second")).DisposeAsync();

        guarded.Should().BeAssignableTo<IResettableExecutor>();
        inner.Handled.Should().Be(2);
        inner.Resets.Should().Be(2);
    }

    [Fact]
    public async Task ShouldAllowWorkflowReuse_WhenInnerExecutorIsNotResettable()
    {
        var guarded = new TicketIntakeExecutor("intake").WithGuardrails(PolicyWith());
        var desk = new TicketDeskExecutor("desk");
        var workflow = new WorkflowBuilder(guarded).AddEdge(guarded, desk).Build();

        await (await InProcessExecution.RunAsync(workflow, "first")).DisposeAsync();
        var runAgain = async () => await (await InProcessExecution.RunAsync(workflow, "second")).DisposeAsync();

        await runAgain.Should().NotThrowAsync();
        guarded.Should().NotBeAssignableTo<IResettableExecutor>();
        desk.Received.Should().Equal(new Ticket("first"), new Ticket("second"));
    }

    [Fact]
    public async Task ShouldDisposeInnerExecutor_WhenWorkflowRunEnds()
    {
        var inner = new DisposableExecutor("disposable");
        var workflow = new WorkflowBuilder(inner.WithGuardrails(PolicyWith())).Build();

        await (await InProcessExecution.RunAsync(workflow, "hello")).DisposeAsync();

        inner.Disposed.Should().BeTrue();
    }

    [Fact]
    public async Task ShouldApplyInnerExecutorOptions_WhenInnerDoesNotYieldItsResult()
    {
        var inner = new QuietEchoExecutor("quiet");
        var guarded = inner.WithGuardrails(PolicyWith());
        var workflow = new WorkflowBuilder(guarded).WithOutputFrom(guarded).Build();

        await using var run = await InProcessExecution.RunAsync(workflow, "hello");

        Failures(run).Should().BeEmpty();
        inner.Received.Should().Equal("hello");
        Outputs(run).Should().BeEmpty();
    }

    [Fact]
    public void ShouldBeShareableAcrossRuns_WhenInnerExecutorIs()
    {
        var shareable = new FunctionExecutor<string>("shared", (_, _, _) => ValueTask.CompletedTask, declareCrossRunShareable: true);
        var exclusive = new FunctionExecutor<string>("exclusive", (_, _, _) => ValueTask.CompletedTask);

        new ExecutorInstanceBinding(shareable.WithGuardrails(PolicyWith())).SupportsConcurrentSharedExecution.Should().BeTrue();
        new ExecutorInstanceBinding(exclusive.WithGuardrails(PolicyWith())).SupportsConcurrentSharedExecution.Should().BeFalse();
    }

    private static GuardrailPolicy PolicyWith(params IGuardrailRule[] rules) => new("test", rules);

    private static GuardrailPolicy Redacting(string word) => PolicyWith(new ReplacingRule(word, "[redacted]"));

    private static IEnumerable<WorkflowEvent> Failures(Run run) =>
        run.OutgoingEvents.Where(e => e is WorkflowErrorEvent or ExecutorFailedEvent);

    private static IEnumerable<object?> Outputs(Run run) =>
        run.OutgoingEvents.OfType<WorkflowOutputEvent>().Select(e => e.Data);

    private sealed record Ticket(string Body);

    private sealed record TicketSummary(string Text);

    [SendsMessage(typeof(Ticket))]
    [YieldsOutput(typeof(TicketSummary))]
    private sealed class TicketIntakeExecutor(string id) : Executor<string>(id)
    {
        public override async ValueTask HandleAsync(string message, IWorkflowContext context, CancellationToken cancellationToken = default)
        {
            await context.SendMessageAsync(new Ticket(message), targetId: null, cancellationToken);
            await context.YieldOutputAsync(new TicketSummary($"filed: {message}"), cancellationToken);
        }
    }

    [YieldsOutput(typeof(string))]
    private sealed class TicketDeskExecutor(string id) : Executor<Ticket>(id)
    {
        public List<Ticket> Received { get; } = [];

        public override async ValueTask HandleAsync(Ticket message, IWorkflowContext context, CancellationToken cancellationToken = default)
        {
            Received.Add(message);
            await context.YieldOutputAsync($"desk: {message.Body}", cancellationToken);
        }
    }

    private sealed class TriageExecutor(string id) : Executor<string, string>(id)
    {
        protected override ProtocolBuilder ConfigureProtocol(ProtocolBuilder protocolBuilder) =>
            base.ConfigureProtocol(protocolBuilder).SendsMessage<Ticket>();

        public override async ValueTask<string> HandleAsync(string message, IWorkflowContext context, CancellationToken cancellationToken = default)
        {
            await context.SendMessageAsync(new Ticket(message), targetId: null, cancellationToken);
            return $"triaged: {message}";
        }
    }

    private sealed class MultiInputExecutor(string id) : Executor<string>(id)
    {
        public List<object> Received { get; } = [];

        protected override ProtocolBuilder ConfigureProtocol(ProtocolBuilder protocolBuilder) =>
            base.ConfigureProtocol(protocolBuilder).ConfigureRoutes(routes => routes.AddHandler<Ticket>(HandleTicketAsync));

        public override ValueTask HandleAsync(string message, IWorkflowContext context, CancellationToken cancellationToken = default)
        {
            Received.Add(message);
            return ValueTask.CompletedTask;
        }

        private ValueTask HandleTicketAsync(Ticket ticket, IWorkflowContext context, CancellationToken cancellationToken)
        {
            Received.Add(ticket);
            return ValueTask.CompletedTask;
        }
    }

    private sealed class CatchAllExecutor(string id) : Executor<string>(id)
    {
        public List<object> Caught { get; } = [];

        protected override ProtocolBuilder ConfigureProtocol(ProtocolBuilder protocolBuilder)
        {
            Func<PortableValue, IWorkflowContext, CancellationToken, ValueTask> catchAll = CatchAsync;
            return base.ConfigureProtocol(protocolBuilder).ConfigureRoutes(routes => routes.AddCatchAll(catchAll));
        }

        public override ValueTask HandleAsync(string message, IWorkflowContext context, CancellationToken cancellationToken = default) =>
            ValueTask.CompletedTask;

        private ValueTask CatchAsync(PortableValue message, IWorkflowContext context, CancellationToken cancellationToken)
        {
            Caught.Add(message.As<object>()!);
            return ValueTask.CompletedTask;
        }
    }

    private sealed class ChatTurnExecutor(string id) : Executor<IEnumerable<ChatMessage>>(id)
    {
        public int Turns { get; private set; }

        protected override ProtocolBuilder ConfigureProtocol(ProtocolBuilder protocolBuilder) =>
            base.ConfigureProtocol(protocolBuilder).ConfigureRoutes(routes => routes.AddHandler<TurnToken>(TakeTurnAsync));

        public override ValueTask HandleAsync(IEnumerable<ChatMessage> message, IWorkflowContext context, CancellationToken cancellationToken = default) =>
            ValueTask.CompletedTask;

        private ValueTask TakeTurnAsync(TurnToken token, IWorkflowContext context, CancellationToken cancellationToken)
        {
            Turns++;
            return ValueTask.CompletedTask;
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

    private sealed class RecordingRule(List<string> evaluated) : IGuardrailRule
    {
        public string Name => "record";
        public GuardrailPhase Phase => GuardrailPhase.Both;
        public int Order => 100;

        public ValueTask<GuardrailResult> EvaluateAsync(GuardrailContext context, CancellationToken cancellationToken = default)
        {
            evaluated.Add(context.Text);
            return ValueTask.FromResult(GuardrailResult.Passed());
        }
    }

    private sealed class CountingExecutor(string id) : Executor<string>(id)
    {
        private const string CountKey = "count";

        public List<string> Calls { get; } = [];

        public int Count { get; set; }

        public override ValueTask HandleAsync(string message, IWorkflowContext context, CancellationToken cancellationToken = default)
        {
            Count++;
            return ValueTask.CompletedTask;
        }

        protected override ValueTask InitializeAsync(IWorkflowContext context, CancellationToken cancellationToken = default) =>
            Record("initialize");

        protected override ValueTask OnMessageDeliveryStartingAsync(IWorkflowContext context, CancellationToken cancellationToken = default) =>
            Record("delivery-starting");

        protected override ValueTask OnMessageDeliveryFinishedAsync(IWorkflowContext context, CancellationToken cancellationToken = default) =>
            Record("delivery-finished");

        protected override async ValueTask OnCheckpointingAsync(IWorkflowContext context, CancellationToken cancellationToken = default)
        {
            Calls.Add("checkpointing");
            await context.QueueStateUpdateAsync(CountKey, Count, cancellationToken: cancellationToken);
        }

        protected override async ValueTask OnCheckpointRestoredAsync(IWorkflowContext context, CancellationToken cancellationToken = default)
        {
            Calls.Add("restored");
            Count = await context.ReadStateAsync<int>(CountKey, cancellationToken: cancellationToken);
        }

        private ValueTask Record(string call)
        {
            Calls.Add(call);
            return ValueTask.CompletedTask;
        }
    }

    private sealed class ResettableExecutor(string id) : Executor<string>(id), IResettableExecutor
    {
        public int Handled { get; private set; }

        public int Resets { get; private set; }

        public override ValueTask HandleAsync(string message, IWorkflowContext context, CancellationToken cancellationToken = default)
        {
            Handled++;
            return ValueTask.CompletedTask;
        }

        public ValueTask ResetAsync()
        {
            Resets++;
            return ValueTask.CompletedTask;
        }
    }

    private sealed class DisposableExecutor(string id) : Executor<string>(id), IAsyncDisposable
    {
        public bool Disposed { get; private set; }

        public override ValueTask HandleAsync(string message, IWorkflowContext context, CancellationToken cancellationToken = default) =>
            ValueTask.CompletedTask;

        public ValueTask DisposeAsync()
        {
            Disposed = true;
            return ValueTask.CompletedTask;
        }
    }

    private sealed class QuietEchoExecutor(string id)
        : Executor<string, string>(id, new StatefulExecutorOptions { AutoYieldOutputHandlerResultObject = false })
    {
        public List<string> Received { get; } = [];

        public override ValueTask<string> HandleAsync(string message, IWorkflowContext context, CancellationToken cancellationToken = default)
        {
            Received.Add(message);
            return ValueTask.FromResult(message);
        }
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

    private sealed class BlockingRule(string reason) : IGuardrailRule
    {
        public string Name => "block";
        public GuardrailPhase Phase => GuardrailPhase.Both;
        public int Order => 100;

        public ValueTask<GuardrailResult> EvaluateAsync(GuardrailContext context, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(GuardrailResult.Blocked(reason));
    }
}
