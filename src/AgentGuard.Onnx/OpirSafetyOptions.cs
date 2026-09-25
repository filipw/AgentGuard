using AgentGuard.Core.Abstractions;

namespace AgentGuard.Onnx;

/// <summary>
/// Options for the Opir-multilang ONNX content-safety classifier (<see cref="OpirSafetyRule"/>).
/// Opir-multilang is a GLiClass uni-encoder over mDeBERTa-v3-base that scores text against a frozen
/// harm taxonomy (toxicity, hate speech, violence, sexual content, self-harm, harassment) in any
/// language. It is an offline, multilingual content-safety guard - the gap the English-only
/// Defender classifier and cloud-only content-safety APIs leave open.
/// Requires a pre-downloaded ONNX model, the mDeBERTa-v3 SentencePiece tokenizer, and the
/// label-prefix file - see <c>eng/MODELS.md</c>.
/// </summary>
public sealed class OpirSafetyOptions
{
    /// <summary>
    /// Path to the Opir-multilang ONNX model file. The official
    /// <c>knowledgator/opir-multitask-multilang-v1.0</c> repo ships only PyTorch weights, so this is
    /// a frozen-taxonomy ONNX export (see <c>eng/MODELS.md</c>). The download script
    /// defaults to the fp16 build.
    /// </summary>
    public required string ModelPath { get; init; }

    /// <summary>
    /// Path to the mDeBERTa-v3-base SentencePiece model file (<c>spm.model</c>, the 250k multilingual
    /// vocab). The download script fetches it alongside the model.
    /// </summary>
    public required string TokenizerPath { get; init; }

    /// <summary>
    /// Path to the label-prefix file (<c>prefix.json</c>): the frozen taxonomy plus the precomputed
    /// <c>[CLS] &lt;&lt;LABEL&gt;&gt;... &lt;&lt;SEP&gt;&gt;</c> token-id prefix the rule prepends to each input.
    /// </summary>
    public required string PrefixPath { get; init; }

    /// <summary>
    /// Probability threshold (0.0-1.0) above which content is blocked. The decision is
    /// <c>block iff max-over-harm-labels sigmoid(logit) &gt;= Threshold</c>. Default: <c>0.5</c>.
    /// Tunable per deployment: raising it trades recall for fewer false positives.
    /// </summary>
    public float Threshold { get; init; } = 0.5f;

    /// <summary>
    /// Maximum sequence length the model is run with, including the frozen label prefix and the
    /// trailing <c>[SEP]</c>. What remains is the text budget that caps <see cref="WindowSize"/>;
    /// longer input is split into windows rather than truncated. Default: 512 (mDeBERTa-v3 base
    /// sequence length).
    /// </summary>
    public int MaxTokenLength { get; init; } = 512;

    /// <summary>
    /// Maximum number of text tokens per classification window. Input that fits in one window is
    /// classified in a single call. Longer input is split at word boundaries into
    /// overlapping windows (see <see cref="WindowOverlap"/>) that are classified separately: the input
    /// is blocked when any window is, and the scores of the highest-scoring window are reported. Values
    /// above the text budget (<see cref="MaxTokenLength"/> minus the label prefix and <c>[SEP]</c>) are
    /// clamped to it.
    /// <para>
    /// Default: 512, which is clamped to the whole text budget, so input up to a full model window is
    /// classified in one pass. Harmful content surrounded by a lot of benign
    /// text in the same window can be diluted below the threshold; lower this (for example to 128-256)
    /// to trade more model calls and some false-positive risk for sensitivity to such content.
    /// </para>
    /// </summary>
    public int WindowSize { get; init; } = 512;

    /// <summary>
    /// Number of tokens consecutive windows share, so text near a window boundary is also classified
    /// together with what follows it. A passage of up to about this many tokens always lies entirely
    /// within at least one window. Must be smaller than the effective <see cref="WindowSize"/>.
    /// Default: 128.
    /// </summary>
    public int WindowOverlap { get; init; } = 128;

    /// <summary>
    /// Maximum number of windows classified for a single input. Each window is a full model call, so
    /// the cost of the rule grows linearly with input length; this bounds it. Input that needs more
    /// windows is blocked (with <see cref="GuardrailSeverity.Medium"/> severity and
    /// <c>inputTooLong</c> metadata) instead of being passed with part of it never classified.
    /// Set to 0 to remove the limit. Default: 32, which covers roughly 11,000 tokens with the default
    /// window settings.
    /// </summary>
    public int MaxWindows { get; init; } = 32;

    /// <summary>
    /// Whether to include the triggering label, its score, and the full per-label scores in result
    /// metadata. For input split into windows these are the reported window's scores, and the metadata
    /// also carries <c>windowIndex</c> (zero-based), <c>windowCount</c>, <c>windowStart</c> and
    /// <c>windowLength</c> (the character range of that window). Default: true.
    /// </summary>
    public bool IncludeConfidence { get; init; } = true;
}
