namespace AgentGuard.Onnx;

/// <summary>
/// Options for the StackOne Defender prompt injection classifier.
/// The model is bundled with the AgentGuard.Onnx NuGet package - no separate download required.
/// </summary>
public sealed class DefenderPromptInjectionOptions
{
    /// <summary>
    /// Optional custom path to the ONNX model file. If null, the bundled model is used.
    /// </summary>
    public string? ModelPath { get; init; }

    /// <summary>
    /// Optional custom path to the vocab.txt file. If null, the bundled vocab is used.
    /// </summary>
    public string? VocabPath { get; init; }

    /// <summary>
    /// Confidence threshold (0.0–1.0) above which input is classified as prompt injection.
    /// Default: 0.5.
    /// </summary>
    public float Threshold { get; init; } = 0.5f;

    /// <summary>
    /// Maximum input token length. Inputs longer than this are truncated.
    /// Default: 256 (MiniLM max sequence length).
    /// </summary>
    public int MaxTokenLength { get; init; } = 256;

    /// <summary>
    /// Whether to include the confidence score in result metadata.
    /// Default: true.
    /// </summary>
    public bool IncludeConfidence { get; init; } = true;
}
