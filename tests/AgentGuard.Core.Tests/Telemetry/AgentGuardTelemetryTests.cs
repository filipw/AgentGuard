using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Metrics;
using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Guardrails;
using AgentGuard.Core.Streaming;
using AgentGuard.Core.Telemetry;
using FluentAssertions;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Xunit;

namespace AgentGuard.Core.Tests.Telemetry;

// these tests share global state (ActivitySource/Meter) and must not run in parallel
[Collection("Telemetry")]
public class AgentGuardTelemetryTests : IDisposable
{
    // other test classes run pipelines concurrently, so spans stop on other threads too
    private readonly ConcurrentQueue<Activity> _activities = new();
    private readonly ActivityListener _activityListener;
    private readonly MeterListener _meterListener;
    private readonly ConcurrentDictionary<string, ConcurrentQueue<long>> _counterValues = new();
    private readonly ConcurrentDictionary<string, ConcurrentQueue<double>> _histogramValues = new();

    public AgentGuardTelemetryTests()
    {
        _activityListener = new ActivityListener
        {
            ShouldListenTo = source => source.Name == AgentGuardTelemetry.SourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            // use ActivityStopped so tags are guaranteed to be set (using block completed)
            ActivityStopped = activity => _activities.Enqueue(activity)
        };
        ActivitySource.AddActivityListener(_activityListener);

        _meterListener = new MeterListener();
        _meterListener.InstrumentPublished = (instrument, listener) =>
        {
            if (instrument.Meter.Name == AgentGuardTelemetry.SourceName)
                listener.EnableMeasurementEvents(instrument);
        };
        _meterListener.SetMeasurementEventCallback<long>((instrument, measurement, tags, _) =>
            _counterValues.GetOrAdd(instrument.Name, _ => new()).Enqueue(measurement));
        _meterListener.SetMeasurementEventCallback<double>((instrument, measurement, tags, _) =>
            _histogramValues.GetOrAdd(instrument.Name, _ => new()).Enqueue(measurement));
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

    // names unique to one test, so spans from pipelines other test classes run at the same time never match
    private static string UniqueName(string prefix) => $"{prefix}-{Guid.NewGuid():N}";

    private Activity PolicySpan(string operationName, string policyName) =>
        _activities.Last(a => a.OperationName == operationName
            && Equals(a.GetTagItem(AgentGuardTelemetry.Tags.PolicyName), policyName));

    private Activity RuleSpan(string ruleName) =>
        _activities.Last(a => a.OperationName == $"{AgentGuardTelemetry.Spans.RuleEvaluate} {ruleName}");

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
        var policyName = UniqueName("block-policy");
        var ruleName = UniqueName("blocker");
        var rule = new TestRule(ruleName, GuardrailPhase.Input,
            _ => ValueTask.FromResult(GuardrailResult.Blocked("forbidden content", GuardrailSeverity.Medium)));
        var pipeline = new GuardrailPipeline(
            new GuardrailPolicy(policyName, [rule]),
            NullLogger<GuardrailPipeline>.Instance);

        await pipeline.RunAsync(Ctx("bad input"));

        // a block is an expected outcome: it is recorded through tags, and the span status stays unset
        var pipelineSpan = PolicySpan(AgentGuardTelemetry.Spans.PipelineRun, policyName);
        pipelineSpan.GetTagItem(AgentGuardTelemetry.Tags.Outcome).Should().Be("blocked");
        pipelineSpan.GetTagItem(AgentGuardTelemetry.Tags.BlockedReason).Should().Be("forbidden content");
        pipelineSpan.GetTagItem(AgentGuardTelemetry.Tags.Severity).Should().Be("medium");
        pipelineSpan.Status.Should().Be(ActivityStatusCode.Unset);

        var ruleSpan = RuleSpan(ruleName);
        ruleSpan.GetTagItem(AgentGuardTelemetry.Tags.Outcome).Should().Be("blocked");
        ruleSpan.GetTagItem(AgentGuardTelemetry.Tags.BlockedReason).Should().Be("forbidden content");
        ruleSpan.GetTagItem(AgentGuardTelemetry.Tags.Severity).Should().Be("medium");
        ruleSpan.Status.Should().Be(ActivityStatusCode.Unset);
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
    public async Task ShouldNotSetErrorStatus_WhenPipelineBlocks()
    {
        var policyName = UniqueName("no-error-policy");
        var rule = new TestRule(UniqueName("block-rule"), GuardrailPhase.Input,
            _ => ValueTask.FromResult(GuardrailResult.Blocked("blocked")));
        var pipeline = new GuardrailPipeline(
            new GuardrailPolicy(policyName, [rule]),
            NullLogger<GuardrailPipeline>.Instance);

        await pipeline.RunAsync(Ctx("hello"));

        var pipelineSpan = PolicySpan(AgentGuardTelemetry.Spans.PipelineRun, policyName);
        pipelineSpan.Status.Should().Be(ActivityStatusCode.Unset);
        pipelineSpan.StatusDescription.Should().BeNull();
    }

    [Fact]
    public async Task ShouldSetErrorStatusOnRuleSpan_WhenRuleCannotReachAVerdict()
    {
        var policyName = UniqueName("rule-error-policy");
        var ruleName = UniqueName("failing-rule");
        var rule = new TestRule(ruleName, GuardrailPhase.Input,
            _ => ValueTask.FromResult(GuardrailResult.Error(ruleName, ErrorBehavior.FailOpen, "classifier timed out")));
        var pipeline = new GuardrailPipeline(
            new GuardrailPolicy(policyName, [rule]),
            NullLogger<GuardrailPipeline>.Instance);

        var result = await pipeline.RunAsync(Ctx("hello"));

        result.IsBlocked.Should().BeFalse();
        var ruleSpan = RuleSpan(ruleName);
        ruleSpan.Status.Should().Be(ActivityStatusCode.Error);
        ruleSpan.StatusDescription.Should().Be("classifier timed out");
        ruleSpan.GetTagItem(AgentGuardTelemetry.Tags.ErrorType).Should().Be("classifier timed out");
        ruleSpan.GetTagItem(AgentGuardTelemetry.Tags.Outcome).Should().Be("error");
    }

    [Fact]
    public async Task ShouldSetErrorStatus_WhenRuleThrows()
    {
        var policyName = UniqueName("throwing-policy");
        var ruleName = UniqueName("throwing-rule");
        var rule = new TestRule(ruleName, GuardrailPhase.Input,
            _ => throw new InvalidOperationException("model unavailable"));
        var pipeline = new GuardrailPipeline(
            new GuardrailPolicy(policyName, [rule]),
            NullLogger<GuardrailPipeline>.Instance);

        var act = async () => await pipeline.RunAsync(Ctx("hello"));

        await act.Should().ThrowAsync<InvalidOperationException>();
        var ruleSpan = RuleSpan(ruleName);
        ruleSpan.Status.Should().Be(ActivityStatusCode.Error);
        ruleSpan.GetTagItem(AgentGuardTelemetry.Tags.ErrorType).Should().Be(typeof(InvalidOperationException).FullName);
        var pipelineSpan = PolicySpan(AgentGuardTelemetry.Spans.PipelineRun, policyName);
        pipelineSpan.Status.Should().Be(ActivityStatusCode.Error);
        pipelineSpan.StatusDescription.Should().Be("model unavailable");
    }

    [Fact]
    public async Task ShouldNotSetErrorStatus_WhenTheCallerCancels()
    {
        var policyName = UniqueName("cancelled-policy");
        var ruleName = UniqueName("cancelled-rule");
        using var cts = new CancellationTokenSource();
        var rule = new TestRule(ruleName, GuardrailPhase.Input, _ =>
        {
            cts.Cancel();
            cts.Token.ThrowIfCancellationRequested();
            return ValueTask.FromResult(GuardrailResult.Passed());
        });
        var pipeline = new GuardrailPipeline(
            new GuardrailPolicy(policyName, [rule]),
            NullLogger<GuardrailPipeline>.Instance);

        var act = async () => await pipeline.RunAsync(Ctx("hello"), cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
        RuleSpan(ruleName).Status.Should().Be(ActivityStatusCode.Unset);
        PolicySpan(AgentGuardTelemetry.Spans.PipelineRun, policyName).Status.Should().Be(ActivityStatusCode.Unset);
    }

    [Fact]
    public async Task ShouldRecordReaskExhaustionAsABlock_WhenEveryAttemptIsBlocked()
    {
        var policyName = UniqueName("reask-policy");
        var rule = new TestRule(UniqueName("strict"), GuardrailPhase.Output,
            _ => ValueTask.FromResult(GuardrailResult.Blocked("still off-topic", GuardrailSeverity.Low)));
        var chatClient = new Mock<IChatClient>();
        chatClient.Setup(c => c.GetResponseAsync(It.IsAny<IEnumerable<ChatMessage>>(), It.IsAny<ChatOptions>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ChatResponse(new ChatMessage(ChatRole.Assistant, "another attempt")));
        var pipeline = new GuardrailPipeline(
            new GuardrailPolicy(policyName, [rule], reaskOptions: new ReaskOptions { MaxAttempts = 2 }, reaskChatClient: chatClient.Object),
            NullLogger<GuardrailPipeline>.Instance);

        var result = await pipeline.RunAsync(Ctx("off-topic answer", GuardrailPhase.Output));

        result.IsBlocked.Should().BeTrue();
        var reaskSpan = PolicySpan(AgentGuardTelemetry.Spans.PipelineReask, policyName);
        reaskSpan.GetTagItem(AgentGuardTelemetry.Tags.Outcome).Should().Be("blocked");
        reaskSpan.GetTagItem(AgentGuardTelemetry.Tags.BlockedReason).Should().Be("still off-topic");
        reaskSpan.GetTagItem(AgentGuardTelemetry.Tags.Severity).Should().Be("low");
        reaskSpan.Status.Should().Be(ActivityStatusCode.Unset);
    }

    [Fact]
    public async Task ShouldSetErrorStatusOnReaskSpan_WhenTheReaskCallFails()
    {
        var policyName = UniqueName("reask-failure-policy");
        var rule = new TestRule(UniqueName("strict"), GuardrailPhase.Output,
            _ => ValueTask.FromResult(GuardrailResult.Blocked("blocked")));
        var chatClient = new Mock<IChatClient>();
        chatClient.Setup(c => c.GetResponseAsync(It.IsAny<IEnumerable<ChatMessage>>(), It.IsAny<ChatOptions>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new HttpRequestException("LLM endpoint down"));
        var pipeline = new GuardrailPipeline(
            new GuardrailPolicy(policyName, [rule], reaskOptions: new ReaskOptions(), reaskChatClient: chatClient.Object),
            NullLogger<GuardrailPipeline>.Instance);

        var act = async () => await pipeline.RunAsync(Ctx("bad", GuardrailPhase.Output));

        await act.Should().ThrowAsync<HttpRequestException>();
        var reaskSpan = PolicySpan(AgentGuardTelemetry.Spans.PipelineReask, policyName);
        reaskSpan.Status.Should().Be(ActivityStatusCode.Error);
        reaskSpan.GetTagItem(AgentGuardTelemetry.Tags.ErrorType).Should().Be(typeof(HttpRequestException).FullName);
    }

    [Fact]
    public async Task ShouldRecordTheBlockThroughTags_WhenAStreamIsBlocked()
    {
        var policyName = UniqueName("streaming-block-policy");
        var ruleName = UniqueName("streaming-blocker");
        var rule = new TestRule(ruleName, GuardrailPhase.Output, ctx =>
            ValueTask.FromResult(ctx.Text.Contains("secret", StringComparison.Ordinal)
                ? GuardrailResult.Blocked("leaked a secret", GuardrailSeverity.Critical)
                : GuardrailResult.Passed()));
        var pipeline = new StreamingGuardrailPipeline(
            new GuardrailPolicy(policyName, [rule]),
            new ProgressiveStreamingOptions { MinCharsBeforeFirstCheck = 0, EvaluationIntervalChars = 1 });

        await foreach (var _ in pipeline.ProcessStreamAsync(Chunks("the ", "secret ", "is 42"), Ctx("", GuardrailPhase.Output)))
        {
        }

        var streamingSpan = PolicySpan(AgentGuardTelemetry.Spans.StreamingPipeline, policyName);
        streamingSpan.GetTagItem(AgentGuardTelemetry.Tags.Outcome).Should().Be("blocked");
        streamingSpan.GetTagItem(AgentGuardTelemetry.Tags.BlockedReason).Should().Be("leaked a secret");
        streamingSpan.GetTagItem(AgentGuardTelemetry.Tags.Severity).Should().Be("critical");
        streamingSpan.Status.Should().Be(ActivityStatusCode.Unset);

        var ruleSpan = RuleSpan(ruleName);
        ruleSpan.GetTagItem(AgentGuardTelemetry.Tags.BlockedReason).Should().Be("leaked a secret");
        ruleSpan.Status.Should().Be(ActivityStatusCode.Unset);
    }

    [Fact]
    public async Task ShouldSetErrorStatusOnStreamingSpans_WhenRuleCannotReachAVerdict()
    {
        var policyName = UniqueName("streaming-error-policy");
        var ruleName = UniqueName("streaming-failing-rule");
        var rule = new TestRule(ruleName, GuardrailPhase.Output,
            _ => ValueTask.FromResult(GuardrailResult.Error(ruleName, ErrorBehavior.Warn, "judge unreachable")));
        var pipeline = new StreamingGuardrailPipeline(
            new GuardrailPolicy(policyName, [rule]),
            new ProgressiveStreamingOptions { MinCharsBeforeFirstCheck = 0, EvaluationIntervalChars = 1 });

        await foreach (var _ in pipeline.ProcessStreamAsync(Chunks("hello"), Ctx("", GuardrailPhase.Output)))
        {
        }

        var ruleSpan = RuleSpan(ruleName);
        ruleSpan.Status.Should().Be(ActivityStatusCode.Error);
        ruleSpan.GetTagItem(AgentGuardTelemetry.Tags.ErrorType).Should().Be("judge unreachable");
        PolicySpan(AgentGuardTelemetry.Spans.StreamingPipeline, policyName).Status.Should().Be(ActivityStatusCode.Unset);
    }

    [Fact]
    public async Task ShouldSetErrorStatusOnStreamingSpan_WhenTheIncomingStreamFails()
    {
        var policyName = UniqueName("streaming-source-failure");
        var pipeline = new StreamingGuardrailPipeline(new GuardrailPolicy(policyName, []));

        var act = async () =>
        {
            await foreach (var _ in pipeline.ProcessStreamAsync(FailingChunks(), Ctx("", GuardrailPhase.Output)))
            {
            }
        };

        await act.Should().ThrowAsync<IOException>();
        var streamingSpan = PolicySpan(AgentGuardTelemetry.Spans.StreamingPipeline, policyName);
        streamingSpan.Status.Should().Be(ActivityStatusCode.Error);
        streamingSpan.GetTagItem(AgentGuardTelemetry.Tags.ErrorType).Should().Be(typeof(IOException).FullName);
    }

    private static async IAsyncEnumerable<string> Chunks(params string[] chunks)
    {
        foreach (var chunk in chunks)
        {
            await Task.Yield();
            yield return chunk;
        }
    }

    private static async IAsyncEnumerable<string> FailingChunks()
    {
        await Task.Yield();
        yield return "partial answer";
        throw new IOException("connection reset");
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
