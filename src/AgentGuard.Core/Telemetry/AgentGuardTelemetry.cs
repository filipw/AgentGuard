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
        /// <summary>The policy that produced the decision.</summary>
        public const string PolicyName = "agentguard.policy.name";
        /// <summary>The rule being evaluated.</summary>
        public const string RuleName = "agentguard.rule.name";
        /// <summary>The guardrail phase: input or output.</summary>
        public const string Phase = "agentguard.phase";
        /// <summary>passed / blocked / modified / error.</summary>
        public const string Outcome = "agentguard.outcome";
        /// <summary>Severity of a blocked result.</summary>
        public const string Severity = "agentguard.severity";
        /// <summary>The agent the evaluation belongs to.</summary>
        public const string AgentName = "agentguard.agent.name";
        /// <summary>Why a rule blocked.</summary>
        public const string BlockedReason = "agentguard.blocked.reason";
        /// <summary>The execution order of the rule.</summary>
        public const string RuleOrder = "agentguard.rule.order";
        /// <summary>The workflow executor being guarded.</summary>
        public const string ExecutorId = "agentguard.executor.id";
        /// <summary>CLR type name of the workflow message.</summary>
        public const string MessageType = "agentguard.message.type";
        /// <summary>buffered or progressive.</summary>
        public const string StreamingStrategy = "agentguard.streaming.strategy";
        /// <summary>Number of tool calls extracted from a response.</summary>
        public const string ToolCallCount = "agentguard.tool_call.count";
        /// <summary>Configured maximum re-ask attempts.</summary>
        public const string ReaskMaxAttempts = "agentguard.reask.max_attempts";
        /// <summary>Re-ask attempts actually made.</summary>
        public const string ReaskAttemptsUsed = "agentguard.reask.attempts_used";
        /// <summary>Error detail for a rule that could not reach a verdict.</summary>
        public const string ErrorType = "error.type";
    }

    /// <summary>
    /// Well-known span names for AgentGuard telemetry.
    /// </summary>
    public static class Spans
    {
        /// <summary>A full pipeline evaluation.</summary>
        public const string PipelineRun = "agentguard.pipeline.run";
        /// <summary>A single rule evaluation; the rule name is appended.</summary>
        public const string RuleEvaluate = "agentguard.rule.evaluate";
        /// <summary>The re-ask loop.</summary>
        public const string PipelineReask = "agentguard.pipeline.reask";
        /// <summary>A progressive streaming evaluation.</summary>
        public const string StreamingPipeline = "agentguard.streaming.pipeline";
        /// <summary>MAF input guardrails.</summary>
        public const string MiddlewareInput = "agentguard.middleware.input";
        /// <summary>MAF output guardrails.</summary>
        public const string MiddlewareOutput = "agentguard.middleware.output";
        /// <summary>MAF streaming guardrails.</summary>
        public const string MiddlewareStreaming = "agentguard.middleware.streaming";
        /// <summary>Workflow executor guardrails.</summary>
        public const string ExecutorGuard = "agentguard.executor.guard";
    }

    /// <summary>
    /// Well-known outcome values.
    /// </summary>
    public static class Outcomes
    {
        /// <summary>Checked and acceptable.</summary>
        public const string Passed = "passed";
        /// <summary>Rejected.</summary>
        public const string Blocked = "blocked";
        /// <summary>Rewritten.</summary>
        public const string Modified = "modified";
        /// <summary>Could not be checked.</summary>
        public const string Error = "error";
    }
}
