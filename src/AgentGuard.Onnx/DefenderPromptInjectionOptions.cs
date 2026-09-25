using AgentGuard.Core.Abstractions;

namespace AgentGuard.Onnx;

/// <summary>
/// Options for the StackOne Defender multi-head prompt injection classifier (minilm-multihead-v5).
/// The model ships in the Kyoto package that AgentGuard.Onnx depends on - no separate download required.
/// </summary>
/// <remarks>
/// The classifier emits two temperature-calibrated scores: a <c>main</c> injection score and an
/// <c>aux</c> "directed at a human reader" score. Input is blocked when
/// <c>main &gt;= <see cref="MainThreshold"/> AND aux &lt; <see cref="AuxThreshold"/></c>.
/// A high aux score vetoes the block, which rescues imperative-but-benign phrasings such as
/// "show me my orders" that score high on the main head.
/// <para>
/// The default calibration values (<see cref="TemperatureT"/>, <see cref="MainThreshold"/>,
/// <see cref="AuxThreshold"/>) come from the bundled model's
/// <c>classifier_config.json</c> (shipped inside the Kyoto package).
/// </para>
/// </remarks>
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
    /// Main-head score threshold (0.0–1.0). A block requires the main score to be at or above this.
    /// Default: 0.75 (within the F1-optimal plateau on a held-out jailbreak set; raise toward 0.9 to
    /// cut false positives further at some cost to recall).
    /// </summary>
    public float MainThreshold { get; init; } = 0.75f;

    /// <summary>
    /// Aux-head veto threshold (0.0–1.0). A candidate block is rescued (vetoed) when the aux score
    /// is at or above this value. Default: 0.64 (StackOne's cross-validated value). Lowering this
    /// over-rescues attacks on broader benchmarks.
    /// </summary>
    public float AuxThreshold { get; init; } = 0.64f;

    /// <summary>
    /// Temperature for post-hoc calibration. Each raw logit is divided by this before sigmoid:
    /// <c>sigmoid(logit / T)</c>. T &gt; 1 softens overconfident output. Default: 2.41
    /// (the value fitted for minilm-multihead-v5).
    /// </summary>
    public float TemperatureT { get; init; } = 2.41f;

    /// <summary>
    /// Maximum sequence length the model is run with, including the <c>[CLS]</c> and <c>[SEP]</c>
    /// tokens. It caps <see cref="WindowSize"/>; longer input is split into windows rather than
    /// truncated. Default: 256 (MiniLM max sequence length).
    /// </summary>
    public int MaxTokenLength { get; init; } = 256;

    /// <summary>
    /// Maximum number of tokens per classification window. Input that fits in one window is
    /// classified in a single call. Longer input is split at word boundaries into
    /// overlapping windows (see <see cref="WindowOverlap"/>) that are classified separately: the input
    /// is blocked when any window is, and the scores of the highest-scoring blocking window are
    /// reported. Values above what <see cref="MaxTokenLength"/> allows (<c>MaxTokenLength - 2</c>) are
    /// clamped to it.
    /// <para>
    /// Default: 64. The model averages over every token it sees, so a short injection surrounded by
    /// enough benign text in a large window is diluted below the threshold. Measured on the bundled
    /// model with known injections placed in 500 to 10,000 characters of benign prose, 64-token
    /// windows with a 32-token overlap detected 87% of them (254-token windows: 51%), with no false
    /// positives on long benign prose. Smaller windows raise
    /// detection a little further but start flagging benign prose; larger windows dilute injections.
    /// </para>
    /// <para>
    /// Every passage of a long input is classified, so long technical or instructional text (manuals,
    /// READMEs, how-to guides) is more likely to be blocked than a short prompt: the model misreads
    /// some imperative passages as injections.
    /// </para>
    /// </summary>
    public int WindowSize { get; init; } = 64;

    /// <summary>
    /// Number of tokens consecutive windows share, so text near a window boundary is also classified
    /// together with what follows it. An injection of up to about this many tokens always lies entirely
    /// within at least one window. Must be smaller than <see cref="WindowSize"/>. Default: 32.
    /// </summary>
    public int WindowOverlap { get; init; } = 32;

    /// <summary>
    /// Maximum number of windows classified for a single input. Each window is one model call (a few
    /// milliseconds on a modern CPU), so the cost of the rule grows linearly with input length; this
    /// bounds it. Input that needs more
    /// windows is blocked (with <see cref="GuardrailSeverity.Medium"/> severity and
    /// <c>inputTooLong</c> metadata) instead of being passed with part of it never classified.
    /// Set to 0 to remove the limit. Default: 512, which covers roughly 16,000 tokens (on the order of
    /// 70,000 characters of English prose) with the default window settings.
    /// </summary>
    public int MaxWindows { get; init; } = 512;

    /// <summary>
    /// Whether to include the main/aux scores in result metadata. For input split into windows the
    /// metadata also carries <c>windowIndex</c> (zero-based), <c>windowCount</c>, <c>windowStart</c> and
    /// <c>windowLength</c> (the character range of the reported window).
    /// Default: true.
    /// </summary>
    public bool IncludeConfidence { get; init; } = true;
}
