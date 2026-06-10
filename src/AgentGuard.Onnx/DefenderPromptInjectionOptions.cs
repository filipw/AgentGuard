namespace AgentGuard.Onnx;

/// <summary>
/// Options for the StackOne Defender multi-head prompt injection classifier (minilm-multihead-v5).
/// The model is bundled with the AgentGuard.Onnx NuGet package - no separate download required.
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
/// <c>classifier_config.json</c> (see <c>eng/models/minilm-prompt-injection/</c>).
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
    /// Default: 0.5 (StackOne's cross-validated value).
    /// </summary>
    public float MainThreshold { get; init; } = 0.5f;

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
    /// Maximum input token length. Inputs longer than this are truncated.
    /// Default: 256 (MiniLM max sequence length).
    /// </summary>
    public int MaxTokenLength { get; init; } = 256;

    /// <summary>
    /// Whether to include the main/aux scores in result metadata.
    /// Default: true.
    /// </summary>
    public bool IncludeConfidence { get; init; } = true;
}
