namespace AgentGuard.Onnx;

/// <summary>
/// Options for the Opir-multilang ONNX content-safety classifier (<see cref="OpirSafetyRule"/>).
/// Opir-multilang is a GLiClass uni-encoder over mDeBERTa-v3-base that scores text against a frozen
/// harm taxonomy (toxicity, hate speech, violence, sexual content, self-harm, harassment) in any
/// language. It is an offline, multilingual content-safety guard - the gap the English-only
/// Defender classifier and cloud-only content-safety APIs leave open.
/// Requires a pre-downloaded ONNX model, the mDeBERTa-v3 SentencePiece tokenizer, and the
/// label-prefix file - see <c>eng/download-opir-model.sh</c>.
/// </summary>
public sealed class OpirSafetyOptions
{
    /// <summary>
    /// Path to the Opir-multilang ONNX model file. The official
    /// <c>knowledgator/opir-multitask-multilang-v1.0</c> repo ships only PyTorch weights, so this is
    /// a frozen-taxonomy ONNX export (see <c>eng/download-opir-model.sh</c>). The download script
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
    /// Maximum input token length (including the frozen label prefix). Inputs longer than the
    /// remaining text budget are truncated. Default: 512 (mDeBERTa-v3 base sequence length).
    /// </summary>
    public int MaxTokenLength { get; init; } = 512;

    /// <summary>
    /// Whether to include the triggering label, its score, and the full per-label scores in result
    /// metadata. Default: true.
    /// </summary>
    public bool IncludeConfidence { get; init; } = true;
}
