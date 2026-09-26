using AgentGuard.Core.Abstractions;
using Kyoto;

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

    private readonly IDisposable? _session;
    private readonly Func<string, float> _classify;
    private readonly TextWindowSplitter _splitter;
    private readonly OnnxPromptInjectionOptions _options;
    private int _disposed;

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
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when <see cref="OnnxPromptInjectionOptions.Threshold"/> is NaN or outside 0.0-1.0,
    /// <see cref="OnnxPromptInjectionOptions.MaxTokenLength"/> leaves no room for input tokens, or the
    /// window settings are invalid.
    /// </exception>
    /// <exception cref="FileNotFoundException">Thrown when the model or tokenizer file does not exist.</exception>
    public OnnxPromptInjectionRule(OnnxPromptInjectionOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        Validate(options);

        var modelPath = OnnxFileValidation.RequireFile(options.ModelPath, nameof(options.ModelPath), "ONNX model");
        var tokenizerPath = OnnxFileValidation.RequireFile(options.TokenizerPath, nameof(options.TokenizerPath), "tokenizer");

        _options = options;

        // content ids only: the session adds [CLS] and [SEP] itself
        var tokenizer = SentencePieceContentTokenizer.Load(tokenizerPath);

        _splitter = WindowedClassification.CreateSplitter(
            WindowedClassification.CountContentTokens(tokenizer),
            WindowedClassification.OnnxSessionContentBudget(tokenizer, options.MaxTokenLength),
            options.WindowSize,
            options.WindowOverlap,
            nameof(options));

        var session = new OnnxModelSession(modelPath, tokenizer, options.MaxTokenLength);
        _session = session;
        _classify = text => session.Classify(text).InjectionProbability;
    }

    /// <summary>
    /// Internal constructor for testing - classifies with <paramref name="classify"/> (returning the
    /// injection probability) and counts tokens with <paramref name="countTokens"/> instead of loading
    /// the model. <paramref name="session"/>, when given, stands in for the inference session and is
    /// released by <see cref="Dispose"/>.
    /// </summary>
    internal OnnxPromptInjectionRule(
        Func<string, float> classify,
        TokenCounter countTokens,
        OnnxPromptInjectionOptions options,
        IDisposable? session = null)
    {
        Validate(options);
        _options = options;
        _classify = classify;
        _session = session;
        _splitter = WindowedClassification.CreateSplitter(
            countTokens, options.MaxTokenLength - SpecialTokenCount, options.WindowSize, options.WindowOverlap, nameof(options));
    }

    /// <inheritdoc />
    /// <exception cref="ObjectDisposedException">Thrown when the rule has been disposed.</exception>
    public ValueTask<GuardrailResult> EvaluateAsync(
        GuardrailContext context,
        CancellationToken cancellationToken = default)
    {
        // a disposed rule has released its inference session
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);

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
    /// Disposes the underlying ONNX inference session. Calling this again, from any thread, does nothing.
    /// </summary>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
            _session?.Dispose();
    }

    private static void Validate(OnnxPromptInjectionOptions options)
    {
        OptionValidation.RequireProbability(options.Threshold, nameof(options.Threshold), nameof(options));
        OptionValidation.RequireMaxTokenLength(options.MaxTokenLength, SpecialTokenCount, nameof(options));
        WindowedClassification.ValidateWindowOptions(
            options.WindowSize, options.WindowOverlap, options.MaxWindows, nameof(options));
    }
}
