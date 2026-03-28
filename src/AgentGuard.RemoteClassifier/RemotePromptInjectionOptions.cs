using AgentGuard.Core.Abstractions;

namespace AgentGuard.RemoteClassifier;

/// <summary>
/// Options for the remote prompt injection rule.
/// </summary>
public sealed class RemotePromptInjectionOptions
{
    /// <summary>
    /// Labels that indicate an injection was detected. Case-insensitive comparison.
    /// Default: ["jailbreak", "injection", "malicious", "unsafe", "INJECTION"].
    /// </summary>
    public ISet<string> InjectionLabels { get; init; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "jailbreak", "injection", "malicious", "unsafe", "INJECTION"
    };

    /// <summary>
    /// Confidence threshold for the injection label. Results below this threshold are treated as safe.
    /// Default: 0.5.
    /// </summary>
    public float Threshold { get; init; } = 0.5f;

    /// <summary>
    /// Whether to include the confidence score and model info in result metadata.
    /// Default: true.
    /// </summary>
    public bool IncludeConfidence { get; init; } = true;

    /// <summary>
    /// What to do when the remote classifier is unreachable or returns an error.
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
    /// Timeout for the HTTP request. Default: 10 seconds.
    /// </summary>
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(10);
}
