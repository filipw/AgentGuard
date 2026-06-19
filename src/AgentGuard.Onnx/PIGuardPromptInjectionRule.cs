using AgentGuard.Core.Abstractions;
using Microsoft.ML.Tokenizers;

namespace AgentGuard.Onnx;

/// <summary>
/// ONNX-based prompt injection classifier using the PIGuard DeBERTa v3 model
/// (<see href="https://huggingface.co/leolee99/PIGuard">leolee99/PIGuard</see>, ACL 2025, MIT license).
/// Runs fully offline. Order 12 - same DeBERTa slot as <see cref="OnnxPromptInjectionRule"/>.
/// <para>
/// PIGuard is trained with the "Mitigating Over-defense for Free" (MOF) strategy. In AgentGuard's
/// own measurements it matches GPT-4o-class over-defense behaviour while dramatically out-detecting
/// the bundled Defender model on indirect / code-style injection payloads, at the cost of a larger
/// model. Best used either as a standalone guard (default threshold 0.9) or layered after Defender.
/// </para>
/// <para>
/// The model must be downloaded separately - see <c>eng/download-piguard-model.sh</c>. The official
/// repo ships only PyTorch weights, so AgentGuard distributes an ONNX export.
/// </para>
/// </summary>
public sealed class PIGuardPromptInjectionRule : IGuardrailRule, IDisposable
{
    private readonly OnnxModelSession _session;
    private readonly PIGuardPromptInjectionOptions _options;

    /// <inheritdoc />
    public string Name => "piguard-prompt-injection";

    /// <inheritdoc />
    public GuardrailPhase Phase => GuardrailPhase.Input;

    /// <inheritdoc />
    public int Order => 12;

    /// <summary>
    /// Creates a new PIGuard prompt injection rule. Loads the model and tokenizer from disk.
    /// </summary>
    /// <param name="options">Configuration including model and tokenizer file paths.</param>
    /// <exception cref="ArgumentException">Thrown when model or tokenizer path is invalid.</exception>
    public PIGuardPromptInjectionRule(PIGuardPromptInjectionOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var modelPath = OnnxFileValidation.RequireFile(options.ModelPath, nameof(options.ModelPath), "PIGuard ONNX model");
        var tokenizerPath = OnnxFileValidation.RequireFile(options.TokenizerPath, nameof(options.TokenizerPath), "tokenizer");
        if (options.Threshold is < 0f or > 1f)
            throw new ArgumentOutOfRangeException(nameof(options), "Threshold must be between 0.0 and 1.0.");

        _options = options;

        using var tokenizerStream = File.OpenRead(tokenizerPath);
        // content ids only - OnnxModelSession adds [CLS]/[SEP] itself. The default Create() would
        // also prepend a BOS token (id 1 == the CLS id for deberta-v3), producing a double-CLS.
        var tokenizer = SentencePieceTokenizer.Create(
            tokenizerStream, addBeginningOfSentence: false, addEndOfSentence: false);

        _session = new OnnxModelSession(modelPath, tokenizer, options.MaxTokenLength);
    }

    /// <summary>
    /// Internal constructor for testing - accepts a pre-built session.
    /// </summary>
    internal PIGuardPromptInjectionRule(OnnxModelSession session, PIGuardPromptInjectionOptions options)
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

        var (_, injectionProb) = _session.Classify(context.Text);

        if (injectionProb >= _options.Threshold)
        {
            var result = GuardrailResult.Blocked(
                $"PIGuard classifier detected potential prompt injection (confidence: {injectionProb:P1}).",
                GuardrailSeverity.Critical);

            if (_options.IncludeConfidence)
            {
                result = result with
                {
                    Metadata = new Dictionary<string, object>
                    {
                        ["confidence"] = injectionProb,
                        ["model"] = "piguard-deberta-v3",
                        ["threshold"] = _options.Threshold
                    }
                };
            }

            return ValueTask.FromResult(result);
        }

        return ValueTask.FromResult(GuardrailResult.Passed());
    }

    /// <summary>
    /// Disposes the underlying ONNX inference session.
    /// </summary>
    public void Dispose()
    {
        _session.Dispose();
    }
}
