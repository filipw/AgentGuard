using AgentGuard.Core.Abstractions;
using Kyoto;

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
/// Input longer than <see cref="PIGuardPromptInjectionOptions.WindowSize"/> tokens is classified in
/// overlapping windows so that no part of it goes unclassified; the input is blocked when any window
/// is. Shorter input is classified in a single call.
/// </para>
/// <para>
/// The model must be downloaded separately - see <c>eng/MODELS.md</c>. The official
/// repo ships only PyTorch weights, so AgentGuard distributes an ONNX export.
/// </para>
/// </summary>
public sealed class PIGuardPromptInjectionRule : IGuardrailRule, IDisposable
{
    private const string ModelName = "piguard-deberta-v3";

    // the session adds [CLS] and [SEP] around the tokenizer output
    private const int SpecialTokenCount = 2;

    private readonly IDisposable? _session;
    private readonly Func<string, float> _classify;
    private readonly TextWindowSplitter _splitter;
    private readonly PIGuardPromptInjectionOptions _options;
    private int _disposed;

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
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when <see cref="PIGuardPromptInjectionOptions.Threshold"/> is NaN or outside 0.0-1.0,
    /// <see cref="PIGuardPromptInjectionOptions.MaxTokenLength"/> leaves no room for input tokens, or the
    /// window settings are invalid.
    /// </exception>
    /// <exception cref="FileNotFoundException">Thrown when the model or tokenizer file does not exist.</exception>
    public PIGuardPromptInjectionRule(PIGuardPromptInjectionOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        Validate(options);

        var modelPath = OnnxFileValidation.RequireFile(options.ModelPath, nameof(options.ModelPath), "PIGuard ONNX model");
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
    internal PIGuardPromptInjectionRule(
        Func<string, float> classify,
        TokenCounter countTokens,
        PIGuardPromptInjectionOptions options,
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
                "PIGuard", nameof(PIGuardPromptInjectionOptions), _options.MaxWindows));
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
            ? $"PIGuard classifier detected potential prompt injection (confidence: {injectionProb:P1}; {WindowedClassification.DescribeWindow(verdict)})."
            : $"PIGuard classifier detected potential prompt injection (confidence: {injectionProb:P1}).";
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

    private static void Validate(PIGuardPromptInjectionOptions options)
    {
        OptionValidation.RequireProbability(options.Threshold, nameof(options.Threshold), nameof(options));
        OptionValidation.RequireMaxTokenLength(options.MaxTokenLength, SpecialTokenCount, nameof(options));
        WindowedClassification.ValidateWindowOptions(
            options.WindowSize, options.WindowOverlap, options.MaxWindows, nameof(options));
    }
}
