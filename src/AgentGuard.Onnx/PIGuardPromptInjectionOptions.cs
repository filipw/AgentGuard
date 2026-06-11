namespace AgentGuard.Onnx;

/// <summary>
/// Options for the PIGuard ONNX prompt injection classifier (<see cref="PIGuardPromptInjectionRule"/>).
/// PIGuard is a DeBERTa v3 model trained with the "Mitigating Over-defense for Free" strategy; it
/// excels at indirect / code-style injection while keeping benign false positives low.
/// Requires a pre-downloaded ONNX model and the DeBERTa v3 SentencePiece tokenizer.
/// </summary>
public sealed class PIGuardPromptInjectionOptions
{
    /// <summary>
    /// Path to the PIGuard ONNX model file. The official <c>leolee99/PIGuard</c> repo ships only
    /// PyTorch weights, so this is an ONNX export (see <c>eng/download-piguard-model.sh</c>).
    /// </summary>
    public required string ModelPath { get; init; }

    /// <summary>
    /// Path to the DeBERTa v3 SentencePiece model file (<c>spm.model</c>). PIGuard uses the stock
    /// <c>microsoft/deberta-v3-base</c> tokenizer; the download script fetches it from there
    /// (PIGuard's own <c>spm.model</c> on HuggingFace is an unmaterialized Git LFS pointer).
    /// </summary>
    public required string TokenizerPath { get; init; }

    /// <summary>
    /// Confidence threshold (0.0-1.0) above which input is classified as prompt injection.
    /// Default: <c>0.9</c>. PIGuard's argmax (0.5) over-blocks benign text; 0.9 is the measured
    /// operating point where benign false positives drop below the bundled Defender model while
    /// retaining its strong indirect/code-injection recall (see <c>eng/piguard-eval/RESULTS.md</c>).
    /// </summary>
    public float Threshold { get; init; } = 0.9f;

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
