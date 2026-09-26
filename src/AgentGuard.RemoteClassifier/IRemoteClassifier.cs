namespace AgentGuard.RemoteClassifier;

/// <summary>A label and the score a classifier gave it.</summary>
/// <param name="Label">The label (e.g. "INJECTION", "SAFE").</param>
/// <param name="Score">The classifier's confidence in the label (0.0-1.0).</param>
public readonly record struct LabelScore(string Label, float Score);

/// <summary>
/// Result of a remote classification request.
/// </summary>
public sealed class ClassificationResult
{
    /// <summary>The predicted label, the one with the highest score (e.g. "jailbreak", "clean", "injection", "safe").</summary>
    public required string Label { get; init; }

    /// <summary>Confidence score for the predicted label (0.0-1.0).</summary>
    public required float Score { get; init; }

    /// <summary>Optional model name that produced the result.</summary>
    public string? Model { get; init; }

    /// <summary>Optional additional metadata from the classifier.</summary>
    public IReadOnlyDictionary<string, object>? Metadata { get; init; }

    /// <summary>
    /// Every label the classifier scored, in the order it reported them, when it reports more than the
    /// predicted one - for example a text-classification pipeline asked for all scores. When present,
    /// <see cref="RemotePromptInjectionRule"/> compares an injection label's own score with its
    /// threshold, even when another label scored higher. Empty when only the predicted label is known.
    /// </summary>
    public IReadOnlyList<LabelScore> Scores { get; init; } = [];
}

/// <summary>
/// Abstraction for a remote ML text classifier. Implementations call external model servers
/// (Ollama, vLLM, HuggingFace TGI, custom FastAPI endpoints, etc.) via HTTP.
/// </summary>
public interface IRemoteClassifier
{
    /// <summary>
    /// Classifies the given text and returns the result.
    /// </summary>
    /// <param name="text">The text to classify.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Classification result with label and confidence score.</returns>
    Task<ClassificationResult> ClassifyAsync(string text, CancellationToken cancellationToken = default);
}
