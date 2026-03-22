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
    /// Whether to fail open (pass) when the remote classifier is unreachable or returns an error.
    /// Default: true (fail open — same as LLM rules).
    /// </summary>
    public bool FailOpen { get; init; } = true;

    /// <summary>
    /// Timeout for the HTTP request. Default: 10 seconds.
    /// </summary>
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(10);
}
