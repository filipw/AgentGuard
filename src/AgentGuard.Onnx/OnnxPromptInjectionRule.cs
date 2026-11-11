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
/// <para>
/// Input the tokenizer or the model fails on is an error handled by
/// <see cref="OnnxPromptInjectionOptions.OnError"/>; by default the rule fails closed and blocks it.
/// </para>
/// </summary>
public sealed class OnnxPromptInjectionRule : IGuardrailRule, IDisposable
{
    private const string ModelName = "deberta-v3-prompt-injection-v2";

    // the session adds [CLS] and [SEP] around the tokenizer output
    private const int SpecialTokenCount = 2;

    private readonly WindowedClassifier<float> _classifier;
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
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when <see cref="OnnxPromptInjectionOptions.Threshold"/> is NaN or outside 0.0-1.0,
    /// <see cref="OnnxPromptInjectionOptions.MaxTokenLength"/> leaves no room for input tokens, the
    /// window settings are invalid, or <see cref="OnnxPromptInjectionOptions.OnError"/> is not a defined value.
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

        var splitter = WindowedClassification.CreateSplitter(
            WindowedClassification.CountContentTokens(tokenizer),
            WindowedClassification.OnnxSessionContentBudget(tokenizer, options.MaxTokenLength),
            options.WindowSize,
            options.WindowOverlap,
            nameof(options));

        var session = new OnnxModelSession(modelPath, tokenizer, options.MaxTokenLength);
        _classifier = CreateClassifier(
            SentencePieceContentTokenizer.WithRoomForNormalization(tokenizer, text => session.Classify(text).InjectionProbability),
            splitter,
            session);
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
        var splitter = WindowedClassification.CreateSplitter(
            countTokens, options.MaxTokenLength - SpecialTokenCount, options.WindowSize, options.WindowOverlap, nameof(options));
        _classifier = CreateClassifier(classify, splitter, session);
    }

    private WindowedClassifier<float> CreateClassifier(Func<string, float> classify, TextWindowSplitter splitter, IDisposable? session) =>
        new(
            this,
            "ONNX prompt injection",
            nameof(OnnxPromptInjectionOptions),
            session,
            classify,
            probability => probability >= _options.Threshold,
            probability => probability,
            splitter,
            _options.MaxWindows,
            _options.OnError);

    /// <inheritdoc />
    /// <exception cref="ObjectDisposedException">Thrown when the rule has been disposed.</exception>
    public ValueTask<GuardrailResult> EvaluateAsync(
        GuardrailContext context,
        CancellationToken cancellationToken = default)
    {
        if (_classifier.Evaluate(context.Text, cancellationToken, out var verdict) is { } settled)
            return ValueTask.FromResult(settled);

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
    /// Disposes the underlying ONNX inference session. Calling this again, from any thread, does
    /// nothing. An evaluation still running when this is called finishes normally, and the session is
    /// disposed when it does; evaluations started afterwards throw <see cref="ObjectDisposedException"/>.
    /// </summary>
    public void Dispose() => _classifier.Dispose();

    private static void Validate(OnnxPromptInjectionOptions options)
    {
        OptionValidation.RequireProbability(options.Threshold, nameof(options.Threshold), nameof(options));
        OptionValidation.RequireMaxTokenLength(options.MaxTokenLength, SpecialTokenCount, nameof(options));
        WindowedClassification.ValidateWindowOptions(
            options.WindowSize, options.WindowOverlap, options.MaxWindows, nameof(options));
        OptionValidation.RequireErrorBehavior(options.OnError, nameof(options));
    }
}
