namespace AgentGuard.RemoteClassifier;

/// <summary>
/// Result of a remote classification request.
/// </summary>
public sealed class ClassificationResult
{
    /// <summary>The predicted label (e.g. "jailbreak", "clean", "injection", "safe").</summary>
    public required string Label { get; init; }

    /// <summary>Confidence score for the predicted label (0.0–1.0).</summary>
    public required float Score { get; init; }

    /// <summary>Optional model name that produced the result.</summary>
    public string? Model { get; init; }

    /// <summary>Optional additional metadata from the classifier.</summary>
    public IReadOnlyDictionary<string, object>? Metadata { get; init; }
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
