namespace AgentGuard.Core.Streaming;

/// <summary>
/// Configuration for progressive streaming guardrail evaluation.
/// Controls how frequently rules are evaluated as text accumulates during streaming.
/// </summary>
public sealed class ProgressiveStreamingOptions
{
    /// <summary>
    /// Approximate number of characters between progressive evaluation checks.
    /// Uses a character-count heuristic (not exact tokenization) for efficiency.
    /// Default: 200 characters (~50 tokens).
    /// </summary>
    public int EvaluationIntervalChars { get; init; } = 200;

    /// <summary>
    /// Optional time-based evaluation interval. If set, progressive evaluation also triggers
    /// when this duration has elapsed since the last check, regardless of character count.
    /// </summary>
    public TimeSpan? EvaluationIntervalTime { get; init; }

    /// <summary>
    /// Minimum number of characters accumulated before the first progressive evaluation.
    /// Prevents false positives from evaluating very short partial text.
    /// Default: 80 characters (~20 tokens).
    /// </summary>
    public int MinCharsBeforeFirstCheck { get; init; } = 80;

    /// <summary>
    /// Minimum character interval between evaluations for rules using
    /// <see cref="Abstractions.StreamingEvaluationMode.Adaptive"/> mode.
    /// Default: 800 characters (~200 tokens).
    /// </summary>
    public int AdaptiveRuleMinCharInterval { get; init; } = 800;

    /// <summary>
    /// Whether to run all output rules (including <see cref="Abstractions.StreamingEvaluationMode.FinalOnly"/>)
    /// on the complete accumulated text after the stream ends.
    /// Default: true.
    /// </summary>
    public bool RunFinalCheck { get; init; } = true;
}
