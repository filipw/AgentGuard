using AgentGuard.Core.Abstractions;
using Microsoft.ML.Tokenizers;
using Tokenizer = Microsoft.ML.Tokenizers.Tokenizer;

namespace AgentGuard.Onnx;

/// <summary>
/// ONNX-based prompt injection classifier using a fine-tuned DeBERTa v3 model.
/// Runs fully offline with ~10ms inference time. Order 12 — between regex (10) and LLM (15).
/// <para>
/// Recommended model: <c>protectai/deberta-v3-base-prompt-injection-v2</c> from HuggingFace.
/// Download the ONNX model and tokenizer.json, then provide paths via <see cref="OnnxPromptInjectionOptions"/>.
/// </para>
/// </summary>
public sealed class OnnxPromptInjectionRule : IGuardrailRule, IDisposable
{
    private readonly OnnxModelSession _session;
    private readonly OnnxPromptInjectionOptions _options;

    /// <inheritdoc />
    public string Name => "onnx-prompt-injection";

    /// <inheritdoc />
    public GuardrailPhase Phase => GuardrailPhase.Input;

    /// <inheritdoc />
    public int Order => 12;

    /// <summary>
    /// Creates a new ONNX prompt injection rule. Loads the model and tokenizer from disk.
    /// </summary>
    /// <param name="options">Configuration including model and tokenizer file paths.</param>
    /// <exception cref="ArgumentException">Thrown when model or tokenizer path is invalid.</exception>
    public OnnxPromptInjectionRule(OnnxPromptInjectionOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (string.IsNullOrWhiteSpace(options.ModelPath))
            throw new ArgumentException("ModelPath is required.", nameof(options));

        var modelPath = Path.GetFullPath(options.ModelPath);
        if (!File.Exists(modelPath))
            throw new FileNotFoundException($"ONNX model not found at '{modelPath}'.", modelPath);

        if (string.IsNullOrWhiteSpace(options.TokenizerPath))
            throw new ArgumentException("TokenizerPath is required.", nameof(options));

        var tokenizerPath = Path.GetFullPath(options.TokenizerPath);
        if (!File.Exists(tokenizerPath))
            throw new FileNotFoundException($"Tokenizer not found at '{tokenizerPath}'.", tokenizerPath);
        if (options.Threshold is < 0f or > 1f)
            throw new ArgumentOutOfRangeException(nameof(options), "Threshold must be between 0.0 and 1.0.");

        _options = options;

        using var tokenizerStream = File.OpenRead(tokenizerPath);
        var tokenizer = SentencePieceTokenizer.Create(tokenizerStream);

        _session = new OnnxModelSession(modelPath, tokenizer, options.MaxTokenLength);
    }

    /// <summary>
    /// Internal constructor for testing — accepts a pre-built session.
    /// </summary>
    internal OnnxPromptInjectionRule(OnnxModelSession session, OnnxPromptInjectionOptions options)
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
                $"ONNX classifier detected potential prompt injection (confidence: {injectionProb:P1}).",
                GuardrailSeverity.Critical);

            if (_options.IncludeConfidence)
            {
                result = result with
                {
                    Metadata = new Dictionary<string, object>
                    {
                        ["confidence"] = injectionProb,
                        ["model"] = "deberta-v3-prompt-injection-v2",
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
