using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace AgentGuard.Core.Telemetry;

/// <summary>
/// Central telemetry definitions for AgentGuard. All spans originate from
/// <see cref="ActivitySource"/> and all metrics from <see cref="Meter"/>.
/// Consumers opt in via <c>.AddSource("AgentGuard")</c> and <c>.AddMeter("AgentGuard")</c>.
/// </summary>
public static class AgentGuardTelemetry
{
    /// <summary>
    /// The name used for both the <see cref="ActivitySource"/> and <see cref="Meter"/>.
    /// </summary>
    public const string SourceName = "AgentGuard";

    /// <summary>
    /// The <see cref="System.Diagnostics.ActivitySource"/> used by all AgentGuard instrumentation.
    /// </summary>
    public static ActivitySource ActivitySource { get; } = new(SourceName);

    /// <summary>
    /// The <see cref="System.Diagnostics.Metrics.Meter"/> used by all AgentGuard metrics.
    /// </summary>
    public static Meter Meter { get; } = new(SourceName);

    /// <summary>
    /// When true, input/output text is captured as span events. Default is false.
    /// Can also be enabled via the <c>AGENTGUARD_CAPTURE_CONTENT</c> environment variable.
    /// </summary>
    public static bool EnableSensitiveData
    {
        get => _enableSensitiveData ?? IsSensitiveDataEnabledViaEnvironment();
        set => _enableSensitiveData = value;
    }

    private static bool? _enableSensitiveData;

    private static bool IsSensitiveDataEnabledViaEnvironment() =>
        string.Equals(
            Environment.GetEnvironmentVariable("AGENTGUARD_CAPTURE_CONTENT"),
            "true",
            StringComparison.OrdinalIgnoreCase);

    // -- metric instruments --

    internal static readonly Counter<long> PipelineEvaluations =
        Meter.CreateCounter<long>(
            "agentguard.pipeline.evaluations",
            description: "Total guardrail pipeline evaluations");

    internal static readonly Counter<long> RuleEvaluations =
        Meter.CreateCounter<long>(
            "agentguard.rule.evaluations",
            description: "Total individual rule evaluations");

    internal static readonly Counter<long> RuleBlocks =
        Meter.CreateCounter<long>(
            "agentguard.rule.blocks",
            description: "Total rule evaluations that resulted in a block");

    internal static readonly Histogram<double> PipelineDuration =
        Meter.CreateHistogram<double>(
            "agentguard.pipeline.duration",
            unit: "ms",
            description: "Guardrail pipeline execution duration in milliseconds");

    internal static readonly Histogram<double> RuleDuration =
        Meter.CreateHistogram<double>(
            "agentguard.rule.duration",
            unit: "ms",
            description: "Individual rule evaluation duration in milliseconds");

    internal static readonly Counter<long> ReaskAttempts =
        Meter.CreateCounter<long>(
            "agentguard.pipeline.reask.attempts",
            description: "Total re-ask attempts");

    internal static readonly Counter<long> Modifications =
        Meter.CreateCounter<long>(
            "agentguard.pipeline.modifications",
            description: "Total text modifications");

    internal static readonly Counter<long> StreamingRetractions =
        Meter.CreateCounter<long>(
            "agentguard.streaming.retractions",
            description: "Total streaming retractions");

    /// <summary>
    /// Well-known tag keys for AgentGuard telemetry.
    /// </summary>
    public static class Tags
    {
        public const string PolicyName = "agentguard.policy.name";
        public const string RuleName = "agentguard.rule.name";
        public const string Phase = "agentguard.phase";
        public const string Outcome = "agentguard.outcome";
        public const string Severity = "agentguard.severity";
        public const string AgentName = "agentguard.agent.name";
        public const string BlockedReason = "agentguard.blocked.reason";
        public const string RuleOrder = "agentguard.rule.order";
        public const string ExecutorId = "agentguard.executor.id";
        public const string MessageType = "agentguard.message.type";
        public const string StreamingStrategy = "agentguard.streaming.strategy";
        public const string ToolCallCount = "agentguard.tool_call.count";
        public const string ReaskMaxAttempts = "agentguard.reask.max_attempts";
        public const string ReaskAttemptsUsed = "agentguard.reask.attempts_used";
        public const string ErrorType = "error.type";
    }

    /// <summary>
    /// Well-known span names for AgentGuard telemetry.
    /// </summary>
    public static class Spans
    {
        public const string PipelineRun = "agentguard.pipeline.run";
        public const string RuleEvaluate = "agentguard.rule.evaluate";
        public const string PipelineReask = "agentguard.pipeline.reask";
        public const string StreamingPipeline = "agentguard.streaming.pipeline";
        public const string MiddlewareInput = "agentguard.middleware.input";
        public const string MiddlewareOutput = "agentguard.middleware.output";
        public const string MiddlewareStreaming = "agentguard.middleware.streaming";
        public const string ExecutorGuard = "agentguard.executor.guard";
    }

    /// <summary>
    /// Well-known outcome values.
    /// </summary>
    public static class Outcomes
    {
        public const string Passed = "passed";
        public const string Blocked = "blocked";
        public const string Modified = "modified";
        public const string Error = "error";
    }
}
