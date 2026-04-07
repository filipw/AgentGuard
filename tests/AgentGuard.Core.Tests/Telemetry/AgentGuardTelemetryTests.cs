using System.Diagnostics;
using System.Diagnostics.Metrics;
using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Guardrails;
using AgentGuard.Core.Telemetry;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace AgentGuard.Core.Tests.Telemetry;

// these tests share global state (ActivitySource/Meter) and must not run in parallel
[Collection("Telemetry")]
public class AgentGuardTelemetryTests : IDisposable
{
    private readonly List<Activity> _activities = [];
    private readonly ActivityListener _activityListener;
    private readonly MeterListener _meterListener;
    private readonly Dictionary<string, List<long>> _counterValues = [];
    private readonly Dictionary<string, List<double>> _histogramValues = [];

    public AgentGuardTelemetryTests()
    {
        _activityListener = new ActivityListener
        {
            ShouldListenTo = source => source.Name == AgentGuardTelemetry.SourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            // use ActivityStopped so tags are guaranteed to be set (using block completed)
            ActivityStopped = activity => _activities.Add(activity)
        };
        ActivitySource.AddActivityListener(_activityListener);

        _meterListener = new MeterListener();
        _meterListener.InstrumentPublished = (instrument, listener) =>
        {
            if (instrument.Meter.Name == AgentGuardTelemetry.SourceName)
                listener.EnableMeasurementEvents(instrument);
        };
        _meterListener.SetMeasurementEventCallback<long>((instrument, measurement, tags, _) =>
        {
            if (!_counterValues.ContainsKey(instrument.Name))
                _counterValues[instrument.Name] = [];
            _counterValues[instrument.Name].Add(measurement);
        });
        _meterListener.SetMeasurementEventCallback<double>((instrument, measurement, tags, _) =>
        {
            if (!_histogramValues.ContainsKey(instrument.Name))
                _histogramValues[instrument.Name] = [];
            _histogramValues[instrument.Name].Add(measurement);
        });
        _meterListener.Start();
    }

    public void Dispose()
    {
        _activityListener.Dispose();
        _meterListener.Dispose();
        GC.SuppressFinalize(this);
    }

    private static GuardrailContext Ctx(string text, GuardrailPhase phase = GuardrailPhase.Input) =>
        new() { Text = text, Phase = phase };

    [Fact]
    public async Task ShouldEmitPipelineSpan_WhenRunningPipeline()
    {
        var pipeline = new GuardrailPipeline(
            new GuardrailPolicy("test-policy", []),
            NullLogger<GuardrailPipeline>.Instance);

        await pipeline.RunAsync(Ctx("hello"));

        var pipelineSpan = _activities.LastOrDefault(a =>
            a.OperationName == AgentGuardTelemetry.Spans.PipelineRun);
        pipelineSpan.Should().NotBeNull();
        pipelineSpan!.GetTagItem(AgentGuardTelemetry.Tags.PolicyName).Should().Be("test-policy");
        pipelineSpan.GetTagItem(AgentGuardTelemetry.Tags.Phase).Should().Be("input");
        pipelineSpan.GetTagItem(AgentGuardTelemetry.Tags.Outcome).Should().Be("passed");
    }

    [Fact]
    public async Task ShouldEmitRuleSpans_ForEachRule()
    {
        var r1 = new TestRule("rule-one", GuardrailPhase.Input, _ => ValueTask.FromResult(GuardrailResult.Passed()));
        var r2 = new TestRule("rule-two", GuardrailPhase.Input, _ => ValueTask.FromResult(GuardrailResult.Passed()));
        var pipeline = new GuardrailPipeline(
            new GuardrailPolicy("test", [r1, r2]),
            NullLogger<GuardrailPipeline>.Instance);

        await pipeline.RunAsync(Ctx("hello"));

        // look for spans with these unique rule names
        _activities.Should().Contain(a =>
            a.OperationName.Contains("rule-one", StringComparison.Ordinal));
        _activities.Should().Contain(a =>
            a.OperationName.Contains("rule-two", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ShouldRecordBlockOutcome_WhenRuleBlocks()
    {
        var rule = new TestRule("blocker", GuardrailPhase.Input,
            _ => ValueTask.FromResult(GuardrailResult.Blocked("forbidden content")));
        var pipeline = new GuardrailPipeline(
            new GuardrailPolicy("test", [rule]),
            NullLogger<GuardrailPipeline>.Instance);

        await pipeline.RunAsync(Ctx("bad input"));

        // verify pipeline span has blocked outcome and error status
        var pipelineSpan = _activities.Last(a =>
            a.OperationName == AgentGuardTelemetry.Spans.PipelineRun);
        pipelineSpan.GetTagItem(AgentGuardTelemetry.Tags.Outcome).Should().Be("blocked");
        pipelineSpan.Status.Should().Be(ActivityStatusCode.Error);

        // verify rule span has blocked outcome
        var ruleSpan = _activities.Last(a =>
            a.OperationName.Contains("blocker", StringComparison.Ordinal));
        ruleSpan.GetTagItem(AgentGuardTelemetry.Tags.Outcome).Should().Be("blocked");
        ruleSpan.GetTagItem(AgentGuardTelemetry.Tags.BlockedReason).Should().Be("forbidden content");
        ruleSpan.Status.Should().Be(ActivityStatusCode.Error);
    }

    [Fact]
    public async Task ShouldRecordDurationMetrics()
    {
        var rule = new TestRule("fast-rule", GuardrailPhase.Input,
            _ => ValueTask.FromResult(GuardrailResult.Passed()));
        var pipeline = new GuardrailPipeline(
            new GuardrailPolicy("test", [rule]),
            NullLogger<GuardrailPipeline>.Instance);

        await pipeline.RunAsync(Ctx("hello"));
        _meterListener.RecordObservableInstruments();

        _histogramValues.Should().ContainKey("agentguard.pipeline.duration");
        _histogramValues["agentguard.pipeline.duration"].Should().HaveCountGreaterOrEqualTo(1);
        _histogramValues["agentguard.pipeline.duration"].Last().Should().BeGreaterOrEqualTo(0);

        _histogramValues.Should().ContainKey("agentguard.rule.duration");
        _histogramValues["agentguard.rule.duration"].Should().HaveCountGreaterOrEqualTo(1);
    }

    [Fact]
    public async Task ShouldRecordPipelineEvaluationCounter()
    {
        var pipeline = new GuardrailPipeline(
            new GuardrailPolicy("counter-test", []),
            NullLogger<GuardrailPipeline>.Instance);

        await pipeline.RunAsync(Ctx("hello"));
        _meterListener.RecordObservableInstruments();

        _counterValues.Should().ContainKey("agentguard.pipeline.evaluations");
        _counterValues["agentguard.pipeline.evaluations"].Should().HaveCountGreaterOrEqualTo(1);
    }

    [Fact]
    public async Task ShouldRecordRuleBlockCounter_WhenRuleBlocks()
    {
        var rule = new TestRule("counter-blocker", GuardrailPhase.Input,
            _ => ValueTask.FromResult(GuardrailResult.Blocked("no")));
        var pipeline = new GuardrailPipeline(
            new GuardrailPolicy("test", [rule]),
            NullLogger<GuardrailPipeline>.Instance);

        await pipeline.RunAsync(Ctx("bad"));
        _meterListener.RecordObservableInstruments();

        _counterValues.Should().ContainKey("agentguard.rule.blocks");
        _counterValues["agentguard.rule.blocks"].Should().HaveCountGreaterOrEqualTo(1);
    }

    [Fact]
    public async Task ShouldSetErrorStatus_WhenPipelineBlocks()
    {
        var rule = new TestRule("err-rule", GuardrailPhase.Input,
            _ => ValueTask.FromResult(GuardrailResult.Blocked("blocked")));
        var pipeline = new GuardrailPipeline(
            new GuardrailPolicy("test", [rule]),
            NullLogger<GuardrailPipeline>.Instance);

        await pipeline.RunAsync(Ctx("hello"));

        var pipelineSpan = _activities.Last(a =>
            a.OperationName == AgentGuardTelemetry.Spans.PipelineRun);
        pipelineSpan.Status.Should().Be(ActivityStatusCode.Error);
        pipelineSpan.StatusDescription.Should().Be("blocked");
    }

    [Fact]
    public async Task ShouldIncludePolicyAndPhaseAsTags()
    {
        var rule = new TestRule("tag-rule", GuardrailPhase.Output,
            _ => ValueTask.FromResult(GuardrailResult.Passed()));
        var pipeline = new GuardrailPipeline(
            new GuardrailPolicy("my-policy", [rule]),
            NullLogger<GuardrailPipeline>.Instance);

        await pipeline.RunAsync(Ctx("hello", GuardrailPhase.Output));

        var pipelineSpan = _activities.Last(a =>
            a.OperationName == AgentGuardTelemetry.Spans.PipelineRun);
        pipelineSpan.GetTagItem(AgentGuardTelemetry.Tags.PolicyName).Should().Be("my-policy");
        pipelineSpan.GetTagItem(AgentGuardTelemetry.Tags.Phase).Should().Be("output");
    }

    [Fact]
    public async Task ShouldRecordModificationOutcome_WhenRuleModifies()
    {
        var rule = new TestRule("modifier", GuardrailPhase.Input,
            _ => ValueTask.FromResult(GuardrailResult.Modified("cleaned", "redacted PII")));
        var pipeline = new GuardrailPipeline(
            new GuardrailPolicy("test", [rule]),
            NullLogger<GuardrailPipeline>.Instance);

        await pipeline.RunAsync(Ctx("hello"));

        var pipelineSpan = _activities.Last(a =>
            a.OperationName == AgentGuardTelemetry.Spans.PipelineRun);
        pipelineSpan.GetTagItem(AgentGuardTelemetry.Tags.Outcome).Should().Be("modified");

        var ruleSpan = _activities.Last(a =>
            a.OperationName.Contains("modifier", StringComparison.Ordinal));
        ruleSpan.GetTagItem(AgentGuardTelemetry.Tags.Outcome).Should().Be("modified");
    }

    [Fact]
    public async Task ShouldIncludeRuleOrderInSpan()
    {
        var rule = new TestRule("ordered-rule", GuardrailPhase.Input, 42,
            _ => ValueTask.FromResult(GuardrailResult.Passed()));
        var pipeline = new GuardrailPipeline(
            new GuardrailPolicy("test", [rule]),
            NullLogger<GuardrailPipeline>.Instance);

        await pipeline.RunAsync(Ctx("hello"));

        var ruleSpan = _activities.Last(a =>
            a.OperationName.Contains("ordered-rule", StringComparison.Ordinal));
        ruleSpan.GetTagItem(AgentGuardTelemetry.Tags.RuleOrder).Should().Be(42);
    }

    [Fact]
    public async Task ShouldRecordRuleEvaluationCounters_ForEachRule()
    {
        var r1 = new TestRule("a", GuardrailPhase.Input, _ => ValueTask.FromResult(GuardrailResult.Passed()));
        var r2 = new TestRule("b", GuardrailPhase.Input, _ => ValueTask.FromResult(GuardrailResult.Passed()));
        var pipeline = new GuardrailPipeline(
            new GuardrailPolicy("test", [r1, r2]),
            NullLogger<GuardrailPipeline>.Instance);

        await pipeline.RunAsync(Ctx("hello"));
        _meterListener.RecordObservableInstruments();

        _counterValues.Should().ContainKey("agentguard.rule.evaluations");
        _counterValues["agentguard.rule.evaluations"].Should().HaveCountGreaterOrEqualTo(2);
    }

    [Fact]
    public async Task ShouldEmitBlockedEventOnRuleSpan_WhenBlocked()
    {
        var rule = new TestRule("event-blocker", GuardrailPhase.Input,
            _ => ValueTask.FromResult(GuardrailResult.Blocked("bad stuff", GuardrailSeverity.Critical)));
        var pipeline = new GuardrailPipeline(
            new GuardrailPolicy("test", [rule]),
            NullLogger<GuardrailPipeline>.Instance);

        await pipeline.RunAsync(Ctx("hello"));

        var ruleSpan = _activities.Last(a =>
            a.OperationName.Contains("event-blocker", StringComparison.Ordinal));
        var blockedEvent = ruleSpan.Events.FirstOrDefault(e => e.Name == "agentguard.rule.blocked");
        blockedEvent.Name.Should().Be("agentguard.rule.blocked");
        blockedEvent.Tags.Should().Contain(t => t.Key == "reason" && t.Value!.ToString() == "bad stuff");
        blockedEvent.Tags.Should().Contain(t => t.Key == "severity" && t.Value!.ToString() == "critical");
    }

    [Fact]
    public async Task ShouldIncludeAgentNameTag_WhenProvided()
    {
        var pipeline = new GuardrailPipeline(
            new GuardrailPolicy("test", []),
            NullLogger<GuardrailPipeline>.Instance);

        var ctx = new GuardrailContext
        {
            Text = "hello",
            Phase = GuardrailPhase.Input,
            AgentName = "test-agent"
        };

        await pipeline.RunAsync(ctx);

        var pipelineSpan = _activities.Last(a =>
            a.OperationName == AgentGuardTelemetry.Spans.PipelineRun);
        pipelineSpan.GetTagItem(AgentGuardTelemetry.Tags.AgentName).Should().Be("test-agent");
    }

    [Fact]
    public void ShouldExposeCorrectSourceName()
    {
        AgentGuardTelemetry.SourceName.Should().Be("AgentGuard");
        AgentGuardTelemetry.ActivitySource.Name.Should().Be("AgentGuard");
        AgentGuardTelemetry.Meter.Name.Should().Be("AgentGuard");
    }

    private class TestRule(string name, GuardrailPhase phase, Func<GuardrailContext, ValueTask<GuardrailResult>> eval) : IGuardrailRule
    {
        public TestRule(string name, GuardrailPhase phase, int order, Func<GuardrailContext, ValueTask<GuardrailResult>> eval) : this(name, phase, eval) => Order = order;
        public string Name => name;
        public GuardrailPhase Phase => phase;
        public int Order { get; } = 100;
        public ValueTask<GuardrailResult> EvaluateAsync(GuardrailContext context, CancellationToken ct = default) => eval(context);
    }
}
