namespace AgentGuard.Onnx;

/// <summary>
/// Options for configuring the ONNX-based prompt injection classifier.
/// Requires a pre-downloaded ONNX model and HuggingFace tokenizer file.
/// </summary>
public sealed class OnnxPromptInjectionOptions
{
    /// <summary>
    /// Path to the ONNX model file (e.g. model.onnx from protectai/deberta-v3-base-prompt-injection-v2).
    /// </summary>
    public required string ModelPath { get; init; }

    /// <summary>
    /// Path to the SentencePiece model file (spm.model) for the tokenizer.
    /// For <c>protectai/deberta-v3-base-prompt-injection-v2</c>, download the <c>spm.model</c> file from HuggingFace.
    /// </summary>
    public required string TokenizerPath { get; init; }

    /// <summary>
    /// Confidence threshold (0.0–1.0) above which input is classified as prompt injection.
    /// Default: 0.5 (matching the model's recommended threshold).
    /// </summary>
    public float Threshold { get; init; } = 0.5f;

    /// <summary>
    /// Maximum input token length. Inputs longer than this are truncated.
    /// Default: 512 (DeBERTa v3 base max sequence length).
    /// </summary>
    public int MaxTokenLength { get; init; } = 512;

    /// <summary>
    /// Whether to include the confidence score in result metadata.
    /// Default: true.
    /// </summary>
    public bool IncludeConfidence { get; init; } = true;
}
