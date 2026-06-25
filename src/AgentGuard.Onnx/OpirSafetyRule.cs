using AgentGuard.Core.Abstractions;
using Kyoto;

namespace AgentGuard.Onnx;

/// <summary>
/// ONNX-based, offline, multilingual content-safety classifier using the Opir-multilang model
/// (<see href="https://huggingface.co/knowledgator/opir-multitask-multilang-v1.0">knowledgator/opir-multitask-multilang-v1.0</see>,
/// GLiClass uni-encoder over mDeBERTa-v3-base, Apache-2.0). Runs fully offline. Order 50 - the
/// content-safety lane, alongside <c>ContentSafetyRule</c>.
/// <para>
/// Scores each input against a frozen harm taxonomy (toxicity, hate speech, violence, sexual
/// content, self-harm, harassment) and blocks when the strongest per-label probability reaches the
/// threshold. Its niche is <b>non-English</b> content safety: the bundled Defender classifier is
/// English-only (~0% recall off-English) and cloud content-safety APIs are per-call and PII-bound,
/// so this fills an offline multilingual gap rather than replacing them. See
/// <c>eng/opir-eval/RESULTS.md</c> for measured recall/FPR across de/es/ru/ar/zh/hi.
/// </para>
/// <para>
/// The model must be downloaded separately - see <c>eng/download-opir-model.sh</c>. The official
/// repo ships only PyTorch weights, so AgentGuard distributes a frozen-taxonomy ONNX export.
/// </para>
/// </summary>
public sealed class OpirSafetyRule : IGuardrailRule, IDisposable
{
    private readonly OpirModelSession _session;
    private readonly OpirSafetyOptions _options;

    /// <inheritdoc />
    public string Name => "opir-content-safety";

    /// <inheritdoc />
    public GuardrailPhase Phase => GuardrailPhase.Input;

    /// <inheritdoc />
    public int Order => 50;

    /// <summary>
    /// Creates a new Opir content-safety rule. Loads (or reuses a pooled) ONNX session, the
    /// mDeBERTa SentencePiece tokenizer, and the frozen-taxonomy prefix from disk.
    /// </summary>
    /// <param name="options">Configuration including model, tokenizer, and prefix file paths.</param>
    /// <exception cref="ArgumentException">Thrown when a required path is missing or the threshold is out of range.</exception>
    /// <exception cref="FileNotFoundException">Thrown when a configured file does not exist.</exception>
    public OpirSafetyRule(OpirSafetyOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var modelPath = OnnxFileValidation.RequireFile(options.ModelPath, nameof(options.ModelPath), "Opir ONNX model");
        var tokenizerPath = OnnxFileValidation.RequireFile(options.TokenizerPath, nameof(options.TokenizerPath), "mDeBERTa SentencePiece tokenizer");
        var prefixPath = OnnxFileValidation.RequireFile(options.PrefixPath, nameof(options.PrefixPath), "Opir prefix.json");

        if (options.Threshold is < 0f or > 1f)
            throw new ArgumentOutOfRangeException(nameof(options), "Threshold must be between 0.0 and 1.0.");

        _options = options;
        _session = OpirModelSession.Acquire(modelPath, tokenizerPath, prefixPath, options.MaxTokenLength);
    }

    /// <summary>
    /// Internal constructor for testing - accepts a pre-built session.
    /// </summary>
    internal OpirSafetyRule(OpirModelSession session, OpirSafetyOptions options)
    {
        _session = session;
        _options = options;
    }

    /// <inheritdoc />
    public ValueTask<GuardrailResult> EvaluateAsync(
        GuardrailContext context,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(context.Text))
            return ValueTask.FromResult(GuardrailResult.Passed());

        var score = _session.Classify(context.Text);

        if (score.MaxProbability >= _options.Threshold)
        {
            var result = GuardrailResult.Blocked(
                $"Opir content-safety classifier flagged '{score.MaxLabel}' (confidence: {score.MaxProbability:P1}).",
                GuardrailSeverity.High);

            if (_options.IncludeConfidence)
            {
                var perLabel = new Dictionary<string, object>(_session.Labels.Count);
                for (var i = 0; i < _session.Labels.Count; i++)
                    perLabel[_session.Labels[i]] = score.LabelProbabilities[i];

                result = result with
                {
                    Metadata = new Dictionary<string, object>
                    {
                        ["label"] = score.MaxLabel,
                        ["confidence"] = score.MaxProbability,
                        ["scores"] = perLabel,
                        ["model"] = "opir-multilang-mdeberta-v3",
                        ["threshold"] = _options.Threshold
                    }
                };
            }

            return ValueTask.FromResult(result);
        }

        return ValueTask.FromResult(GuardrailResult.Passed());
    }

    /// <summary>
    /// Releases this rule's reference to the pooled ONNX inference session.
    /// </summary>
    public void Dispose()
    {
        _session.Dispose();
    }
}
