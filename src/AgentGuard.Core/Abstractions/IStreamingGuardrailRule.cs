namespace AgentGuard.Core.Abstractions;

/// <summary>
/// Controls when a rule is evaluated during progressive streaming.
/// </summary>
public enum StreamingEvaluationMode
{
    /// <summary>
    /// Evaluate on every progressive check cycle. Suitable for fast, cheap rules (regex, local).
    /// </summary>
    EveryCheck,

    /// <summary>
    /// Only evaluate once all text has been accumulated. Suitable for expensive rules (LLM-based)
    /// or rules that need full context (groundedness checking).
    /// </summary>
    FinalOnly,

    /// <summary>
    /// Evaluate progressively but with a minimum token interval between invocations.
    /// Balances early detection against cost. The interval is configured via
    /// <see cref="ProgressiveStreamingOptions.AdaptiveRuleMinTokenInterval"/>.
    /// </summary>
    Adaptive
}

/// <summary>
/// Optional interface that <see cref="IGuardrailRule"/> implementations can implement
/// to declare their preferred evaluation behavior during progressive streaming.
/// Rules that do not implement this interface are assigned a default mode:
/// LLM-based rules default to <see cref="StreamingEvaluationMode.FinalOnly"/>,
/// all others default to <see cref="StreamingEvaluationMode.EveryCheck"/>.
/// </summary>
public interface IStreamingGuardrailRule
{
    /// <summary>
    /// The evaluation mode for this rule during progressive streaming.
    /// </summary>
    StreamingEvaluationMode StreamingMode { get; }

    /// <summary>
    /// Minimum number of accumulated tokens before this rule's first progressive evaluation.
    /// Defaults to 0 (start checking immediately).
    /// </summary>
    int MinTokensBeforeFirstCheck => 0;
}
