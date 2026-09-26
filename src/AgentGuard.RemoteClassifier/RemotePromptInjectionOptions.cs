using AgentGuard.Core.Abstractions;

namespace AgentGuard.RemoteClassifier;

/// <summary>
/// Options for the remote prompt injection rule.
/// </summary>
public sealed class RemotePromptInjectionOptions
{
    /// <summary>
    /// Labels that indicate an injection was detected, matched ignoring case and independently of the
    /// current culture, whatever comparer the set itself uses. Must contain at least one label.
    /// Default: ["jailbreak", "injection", "malicious", "unsafe", "INJECTION"].
    /// </summary>
    public ISet<string> InjectionLabels { get; init; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "jailbreak", "injection", "malicious", "unsafe", "INJECTION"
    };

    /// <summary>
    /// Confidence threshold for the injection label (0.0-1.0; NaN is rejected). Input is blocked when an
    /// injection label's score is at or above it: the predicted label's score, or, when the classifier
    /// reports every label's score (<see cref="ClassificationResult.Scores"/>), the injection label's own
    /// score even if another label scored higher. Default: 0.5.
    /// </summary>
    public float Threshold { get; init; } = 0.5f;

    /// <summary>
    /// Whether to include the confidence score and model info in result metadata.
    /// Default: true.
    /// </summary>
    public bool IncludeConfidence { get; init; } = true;

    /// <summary>
    /// What to do when the remote classifier is unreachable, times out, returns an error, or returns
    /// a result without a usable label and score.
    /// Default: <see cref="ErrorBehavior.FailOpen"/>.
    /// </summary>
    public ErrorBehavior OnError { get; init; } = ErrorBehavior.FailOpen;

    /// <summary>
    /// Backward-compatible alias for <see cref="OnError"/>.
    /// Setting this to true maps to <see cref="ErrorBehavior.FailOpen"/>,
    /// false maps to <see cref="ErrorBehavior.FailClosed"/>.
    /// Prefer using <see cref="OnError"/> directly for the full range of options.
    /// </summary>
    [Obsolete("Use OnError instead. FailOpen = true → OnError = FailOpen, FailOpen = false → OnError = FailClosed.")]
    public bool FailOpen
    {
        get => OnError == ErrorBehavior.FailOpen;
        init => OnError = value ? ErrorBehavior.FailOpen : ErrorBehavior.FailClosed;
    }

    /// <summary>
    /// Timeout for the classification call: a positive time span, or <c>Timeout.InfiniteTimeSpan</c>
    /// for none. Default: 10 seconds.
    /// </summary>
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(10);
}
