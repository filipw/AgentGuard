using AgentGuard.Core.Abstractions;
using Kyoto;
using Microsoft.ML.Tokenizers;
using Tokenizer = Microsoft.ML.Tokenizers.Tokenizer;

namespace AgentGuard.Onnx;

/// <summary>
/// ONNX-based prompt injection classifier using a fine-tuned DeBERTa v3 model.
/// Runs fully offline with ~10ms inference time. Order 12 - between regex (10) and LLM (15).
/// <para>
/// Recommended model: <c>protectai/deberta-v3-base-prompt-injection-v2</c> from HuggingFace.
/// Download the ONNX model and tokenizer.json, then provide paths via <see cref="OnnxPromptInjectionOptions"/>.
/// </para>
/// <para>
/// Input longer than <see cref="OnnxPromptInjectionOptions.WindowSize"/> tokens is classified in
/// overlapping windows so that no part of it goes unclassified; the input is blocked when any window
/// is. Shorter input is classified in a single call.
/// </para>
/// </summary>
public sealed class OnnxPromptInjectionRule : IGuardrailRule, IDisposable
{
    private const string ModelName = "deberta-v3-prompt-injection-v2";

    // the session adds [CLS] and [SEP] around the tokenizer output
    private const int SpecialTokenCount = 2;

    private readonly OnnxModelSession? _session;
    private readonly Func<string, float> _classify;
    private readonly TextWindowSplitter _splitter;
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

        var modelPath = OnnxFileValidation.RequireFile(options.ModelPath, nameof(options.ModelPath), "ONNX model");
        var tokenizerPath = OnnxFileValidation.RequireFile(options.TokenizerPath, nameof(options.TokenizerPath), "tokenizer");
        if (options.Threshold is < 0f or > 1f)
            throw new ArgumentOutOfRangeException(nameof(options), "Threshold must be between 0.0 and 1.0.");
        WindowedClassification.ValidateWindowOptions(
            options.WindowSize, options.WindowOverlap, options.MaxWindows, nameof(options));

        _options = options;

        using var tokenizerStream = File.OpenRead(tokenizerPath);
        var tokenizer = SentencePieceTokenizer.Create(tokenizerStream);

        _splitter = WindowedClassification.CreateSplitter(
            WindowedClassification.CountContentTokens(tokenizer),
            WindowedClassification.OnnxSessionContentBudget(tokenizer, options.MaxTokenLength),
            options.WindowSize,
            options.WindowOverlap,
            nameof(options));

        _session = new OnnxModelSession(modelPath, tokenizer, options.MaxTokenLength);
        _classify = Classify;
    }

    /// <summary>
    /// Internal constructor for testing - classifies with <paramref name="classify"/> (returning the
    /// injection probability) and counts tokens with <paramref name="countTokens"/> instead of loading
    /// the model.
    /// </summary>
    internal OnnxPromptInjectionRule(
        Func<string, float> classify, TokenCounter countTokens, OnnxPromptInjectionOptions options)
    {
        _options = options;
        _classify = classify;
        WindowedClassification.ValidateWindowOptions(
            options.WindowSize, options.WindowOverlap, options.MaxWindows, nameof(options));
        _splitter = WindowedClassification.CreateSplitter(
            countTokens, options.MaxTokenLength - SpecialTokenCount, options.WindowSize, options.WindowOverlap, nameof(options));
    }

    /// <inheritdoc />
    public ValueTask<GuardrailResult> EvaluateAsync(
        GuardrailContext context,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(context.Text))
            return ValueTask.FromResult(GuardrailResult.Passed());

        if (!_splitter.TrySplit(context.Text, _options.MaxWindows, out var windows))
        {
            return ValueTask.FromResult(WindowedClassification.InputTooLong(
                "ONNX prompt injection", nameof(OnnxPromptInjectionOptions), _options.MaxWindows));
        }

        var verdict = WindowedClassification.Classify(
            context.Text,
            windows,
            _classify,
            probability => probability >= _options.Threshold,
            probability => probability,
            cancellationToken);

        if (!verdict.IsBlocked)
            return ValueTask.FromResult(GuardrailResult.Passed());

        var injectionProb = verdict.Score;
        var reason = verdict.IsWindowed
            ? $"ONNX classifier detected potential prompt injection (confidence: {injectionProb:P1}; {WindowedClassification.DescribeWindow(verdict)})."
            : $"ONNX classifier detected potential prompt injection (confidence: {injectionProb:P1}).";
        var result = GuardrailResult.Blocked(reason, GuardrailSeverity.Critical);

        if (_options.IncludeConfidence)
        {
            var metadata = new Dictionary<string, object>
            {
                ["confidence"] = injectionProb,
                ["model"] = ModelName,
                ["threshold"] = _options.Threshold
            };
            if (verdict.IsWindowed)
                WindowedClassification.AddWindowMetadata(metadata, verdict);

            result = result with { Metadata = metadata };
        }

        return ValueTask.FromResult(result);
    }

    /// <summary>
    /// Disposes the underlying ONNX inference session.
    /// </summary>
    public void Dispose()
    {
        _session?.Dispose();
    }

    private float Classify(string text) => _session!.Classify(text).InjectionProbability;
}
