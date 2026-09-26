using System.Diagnostics;
using AgentGuard.AgentFramework.Workflows;
using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Guardrails;
using AgentGuard.Core.Telemetry;
using FluentAssertions;
using Microsoft.Agents.AI.Workflows;
using Moq;
using Xunit;

namespace AgentGuard.AgentFramework.Workflows.Tests;

public class GuardedExecutorTelemetryTests : IDisposable
{
    private readonly List<Activity> _activities = [];
    private readonly ActivityListener _listener;

    public GuardedExecutorTelemetryTests()
    {
        _listener = new ActivityListener
        {
            ShouldListenTo = source => source.Name == AgentGuardTelemetry.SourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStarted = activity => _activities.Add(activity)
        };
        ActivitySource.AddActivityListener(_listener);
    }

    public void Dispose()
    {
        _listener.Dispose();
        GC.SuppressFinalize(this);
    }

    [Fact]
    public async Task ShouldRecordBlockedOutcomeWithoutErrorStatus_WhenInputBlocked()
    {
        var guarded = new EchoExecutor("echo").WithGuardrails(PolicyWith(Rule(_ => GuardrailResult.Blocked("off-limits", GuardrailSeverity.Medium))));

        var act = () => guarded.HandleAsync("hello", Mock.Of<IWorkflowContext>()).AsTask();
        await act.Should().ThrowAsync<GuardrailViolationException>();

        var span = _activities.Single(a => a.OperationName == AgentGuardTelemetry.Spans.ExecutorGuard);
        span.GetTagItem(AgentGuardTelemetry.Tags.Outcome).Should().Be(AgentGuardTelemetry.Outcomes.Blocked);
        span.GetTagItem(AgentGuardTelemetry.Tags.BlockedReason).Should().Be("off-limits");
        span.GetTagItem(AgentGuardTelemetry.Tags.Severity).Should().Be("medium");
        span.GetTagItem(AgentGuardTelemetry.Tags.ExecutorId).Should().Be("echo");
        span.Status.Should().Be(ActivityStatusCode.Unset);
    }

    [Fact]
    public async Task ShouldRecordBlockedOutcomeWithoutErrorStatus_WhenTypedExecutorOutputBlocked()
    {
        var guarded = new UpperExecutor("upper").WithGuardrails(PolicyWith(
            Rule(context => context.Phase == GuardrailPhase.Output ? GuardrailResult.Blocked("unsafe answer") : GuardrailResult.Passed())));

        var act = () => guarded.HandleAsync("hello", Mock.Of<IWorkflowContext>()).AsTask();
        await act.Should().ThrowAsync<GuardrailViolationException>();

        var input = _activities.Single(a => a.OperationName == $"{AgentGuardTelemetry.Spans.ExecutorGuard} input");
        input.GetTagItem(AgentGuardTelemetry.Tags.Outcome).Should().Be(AgentGuardTelemetry.Outcomes.Passed);

        var output = _activities.Single(a => a.OperationName == $"{AgentGuardTelemetry.Spans.ExecutorGuard} output");
        output.GetTagItem(AgentGuardTelemetry.Tags.Outcome).Should().Be(AgentGuardTelemetry.Outcomes.Blocked);
        output.GetTagItem(AgentGuardTelemetry.Tags.BlockedReason).Should().Be("unsafe answer");
        output.GetTagItem(AgentGuardTelemetry.Tags.Severity).Should().Be("high");
        output.Status.Should().Be(ActivityStatusCode.Unset);
    }

    [Fact]
    public async Task ShouldRecordModifiedOutcome_WhenInputRewritten()
    {
        var guarded = new EchoExecutor("echo").WithGuardrails(PolicyWith(Rule(_ => GuardrailResult.Modified("clean", "rewritten"))));

        await guarded.HandleAsync("dirty", Mock.Of<IWorkflowContext>());

        var span = _activities.Single(a => a.OperationName == AgentGuardTelemetry.Spans.ExecutorGuard);
        span.GetTagItem(AgentGuardTelemetry.Tags.Outcome).Should().Be(AgentGuardTelemetry.Outcomes.Modified);
        span.Status.Should().Be(ActivityStatusCode.Unset);
    }

    [Fact]
    public async Task ShouldRecordErrorStatus_WhenRuleThrows()
    {
        var guarded = new EchoExecutor("echo").WithGuardrails(PolicyWith(Rule(_ => throw new InvalidOperationException("rule crashed"))));

        var act = () => guarded.HandleAsync("hello", Mock.Of<IWorkflowContext>()).AsTask();
        await act.Should().ThrowAsync<InvalidOperationException>();

        var span = _activities.Single(a => a.OperationName == AgentGuardTelemetry.Spans.ExecutorGuard);
        span.GetTagItem(AgentGuardTelemetry.Tags.Outcome).Should().Be(AgentGuardTelemetry.Outcomes.Error);
        span.Status.Should().Be(ActivityStatusCode.Error);
    }

    private static GuardrailPolicy PolicyWith(params IGuardrailRule[] rules) => new("test", rules);

    private static DelegateRule Rule(Func<GuardrailContext, GuardrailResult> evaluate) => new(evaluate);

    private sealed class DelegateRule(Func<GuardrailContext, GuardrailResult> evaluate) : IGuardrailRule
    {
        public string Name => "delegate";
        public GuardrailPhase Phase => GuardrailPhase.Both;
        public int Order => 100;

        public ValueTask<GuardrailResult> EvaluateAsync(GuardrailContext context, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(evaluate(context));
    }

    private sealed class EchoExecutor(string id) : Executor<string>(id)
    {
        public override ValueTask HandleAsync(string message, IWorkflowContext context, CancellationToken cancellationToken = default) =>
            ValueTask.CompletedTask;
    }

    private sealed class UpperExecutor(string id) : Executor<string, string>(id)
    {
        public override ValueTask<string> HandleAsync(string message, IWorkflowContext context, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(message.ToUpperInvariant());
    }
}
