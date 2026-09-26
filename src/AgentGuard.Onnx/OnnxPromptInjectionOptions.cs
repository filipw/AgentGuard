using AgentGuard.Core.Abstractions;

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
    /// Confidence threshold (0.0-1.0; NaN is rejected) at or above which input is classified as prompt
    /// injection. Default: 0.5 (matching the model's recommended threshold).
    /// </summary>
    public float Threshold { get; init; } = 0.5f;

    /// <summary>
    /// Maximum sequence length the model is run with, including the <c>[CLS]</c> and <c>[SEP]</c>
    /// tokens, so it must be at least 3. It caps <see cref="WindowSize"/>; longer input is split into
    /// windows rather than truncated. Default: 512 (DeBERTa v3 base max sequence length).
    /// </summary>
    public int MaxTokenLength { get; init; } = 512;

    /// <summary>
    /// Maximum number of tokens per classification window. Input that fits in one window is
    /// classified in a single call. Longer input is split at word boundaries into
    /// overlapping windows (see <see cref="WindowOverlap"/>) that are classified separately: the input
    /// is blocked when any window is, and the highest window score is reported. Values above what
    /// <see cref="MaxTokenLength"/> allows are clamped to it.
    /// <para>
    /// Default: 510, a full DeBERTa v3 input, so input up to a full model window is classified in one
    /// pass. A short injection surrounded by a lot of benign text in the same
    /// window can be diluted below the threshold; lower this (for example to 128-256) to trade more
    /// model calls and some false-positive risk for sensitivity to such injections. The bundled
    /// Defender classifier uses 64-token windows for that reason.
    /// </para>
    /// </summary>
    public int WindowSize { get; init; } = 510;

    /// <summary>
    /// Number of tokens consecutive windows share, so text near a window boundary is also classified
    /// together with what follows it. An injection of up to about this many tokens always lies entirely
    /// within at least one window. Must be smaller than the effective <see cref="WindowSize"/>.
    /// Default: 128.
    /// </summary>
    public int WindowOverlap { get; init; } = 128;

    /// <summary>
    /// Maximum number of windows classified for a single input. Each window is a full model call, so
    /// the cost of the rule grows linearly with input length; this bounds it. Input that needs more
    /// windows is blocked (with <see cref="GuardrailSeverity.Medium"/> severity and
    /// <c>inputTooLong</c> metadata) instead of being passed with part of it never classified.
    /// Set to 0 to remove the limit. Default: 32, which covers roughly 12,000 tokens with the default
    /// window settings.
    /// </summary>
    public int MaxWindows { get; init; } = 32;

    /// <summary>
    /// Whether to include the confidence score in result metadata. For input split into windows the
    /// metadata also carries <c>windowIndex</c> (zero-based), <c>windowCount</c>, <c>windowStart</c> and
    /// <c>windowLength</c> (the character range of the reported window).
    /// Default: true.
    /// </summary>
    public bool IncludeConfidence { get; init; } = true;
}
