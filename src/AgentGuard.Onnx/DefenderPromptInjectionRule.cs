using System.Reflection;
using AgentGuard.Core.Abstractions;
using Kyoto;
using Microsoft.ML.Tokenizers;

namespace AgentGuard.Onnx;

/// <summary>
/// Prompt injection classifier powered by the StackOne Defender multi-head MiniLM-L6 ONNX model
/// (minilm-multihead-v5). Runs fully offline with fast inference (~8 ms per sample). Order 11 -
/// runs before DeBERTa (order 12).
/// <para>
/// The model emits two temperature-calibrated scores: a main injection score and an auxiliary
/// "directed at a human reader" score. Input is blocked when
/// <c>main &gt;= MainThreshold AND aux &lt; AuxThreshold</c>; a high aux score vetoes the block.
/// This rescues imperative-but-benign phrasings (e.g. "show me my orders") from false positives.
/// </para>
/// <para>
/// Input longer than <see cref="DefenderPromptInjectionOptions.WindowSize"/> tokens is classified in
/// overlapping windows so that no part of it goes unclassified; the input is blocked when any window
/// is. Shorter input is classified in a single call. A word longer than the tokenizer's per-word
/// limit (100 characters), which the model would otherwise see as a single unknown token, is
/// classified in pieces.
/// </para>
/// <para>
/// Input the tokenizer or the model fails on is an error handled by
/// <see cref="DefenderPromptInjectionOptions.OnError"/>; by default the rule fails closed and blocks it.
/// </para>
/// <para>
/// The model ships in the Kyoto package that this package depends on - no separate download required.
/// Based on the <see href="https://github.com/StackOneHQ/defender">StackOne Defender</see> project (Apache 2.0 license).
/// </para>
/// </summary>
public sealed class DefenderPromptInjectionRule : IGuardrailRule, IDisposable
{
    private const string ModelName = "stackone-defender-minilm-multihead-v5";

    // the session adds [CLS] and [SEP] around the content tokens
    private const int SpecialTokenCount = 2;

    private readonly WindowedClassifier<DefenderScore> _classifier;
    private readonly DefenderPromptInjectionOptions _options;

    /// <inheritdoc />
    public string Name => "defender-prompt-injection";

    /// <inheritdoc />
    public GuardrailPhase Phase => GuardrailPhase.Input;

    /// <inheritdoc />
    public int Order => 11;

    /// <summary>
    /// Creates a new Defender prompt injection rule. Uses the bundled model by default.
    /// </summary>
    /// <param name="options">Optional configuration. If null, default options with bundled model are used.</param>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when a threshold is NaN or outside 0.0-1.0, <see cref="DefenderPromptInjectionOptions.TemperatureT"/>
    /// is not a positive finite number, <see cref="DefenderPromptInjectionOptions.MaxTokenLength"/> leaves no
    /// room for input tokens, the window settings are invalid, or
    /// <see cref="DefenderPromptInjectionOptions.OnError"/> is not a defined value.
    /// </exception>
    /// <exception cref="FileNotFoundException">Thrown when a model or vocab file does not exist.</exception>
    public DefenderPromptInjectionRule(DefenderPromptInjectionOptions? options = null)
    {
        _options = options ?? new DefenderPromptInjectionOptions();
        Validate(_options);

        var modelPath = ResolveModelPath(_options.ModelPath, "model_quantized.onnx");
        var vocabPath = ResolveModelPath(_options.VocabPath, "vocab.txt");

        // counts tokens exactly like the session's own tokenizer (same vocab and options), so that
        // input which fits in one window is recognised as such and classified in a single call
        var tokenizer = BertTokenizer.Create(vocabPath, new BertOptions { LowerCaseBeforeTokenization = true });
        var contentTokenBudget = _options.MaxTokenLength - SpecialTokenCount;
        var splitter = WindowedClassification.CreateSplitter(
            text => tokenizer.CountTokens(text),
            contentTokenBudget,
            _options.WindowSize,
            _options.WindowOverlap,
            nameof(options),
            WordPieceTokenization.EncodesWithin(tokenizer, contentTokenBudget));
        var wordBreaker = new LongWordBreaker(WordPieceTokenization.WordsWithinLimit(tokenizer), tokenizer.MaxInputCharsPerWord);

        var session = DefenderModelSession.Acquire(modelPath, vocabPath, _options.MaxTokenLength, _options.TemperatureT);
        _classifier = CreateClassifier(session.Classify, splitter, session, wordBreaker);
    }

    /// <summary>
    /// Internal constructor for testing - classifies with <paramref name="classify"/> and counts tokens
    /// with <paramref name="countTokens"/> instead of loading the model. <paramref name="session"/>, when
    /// given, stands in for the pooled session and is released by <see cref="Dispose"/>.
    /// <paramref name="fitsSession"/> and <paramref name="wordBreaker"/> stand in for the checks the
    /// real tokenizer provides.
    /// </summary>
    internal DefenderPromptInjectionRule(
        Func<string, DefenderScore> classify,
        TokenCounter countTokens,
        DefenderPromptInjectionOptions options,
        IDisposable? session = null,
        SessionFitCheck? fitsSession = null,
        LongWordBreaker? wordBreaker = null)
    {
        Validate(options);
        _options = options;
        var splitter = WindowedClassification.CreateSplitter(
            countTokens, options.MaxTokenLength - SpecialTokenCount, options.WindowSize, options.WindowOverlap, nameof(options), fitsSession);
        _classifier = CreateClassifier(classify, splitter, session, wordBreaker);
    }

    private WindowedClassifier<DefenderScore> CreateClassifier(
        Func<string, DefenderScore> classify, TextWindowSplitter splitter, IDisposable? session, LongWordBreaker? wordBreaker) =>
        new(
            this,
            "Defender",
            nameof(DefenderPromptInjectionOptions),
            session,
            classify,
            score => ShouldBlock(score, _options.MainThreshold, _options.AuxThreshold),
            score => score.Main,
            splitter,
            _options.MaxWindows,
            _options.OnError,
            wordBreaker,
            lineBreaksAsSpaces: true);

    /// <summary>
    /// The multi-head decision rule: block when the main score clears its threshold and the aux
    /// score does not reach the veto threshold. A high aux score (directive aimed at a human reader)
    /// vetoes the block.
    /// </summary>
    internal static bool ShouldBlock(DefenderScore score, float mainThreshold, float auxThreshold) =>
        score.Main >= mainThreshold && score.Aux < auxThreshold;

    /// <inheritdoc />
    /// <exception cref="ObjectDisposedException">Thrown when the rule has been disposed.</exception>
    public ValueTask<GuardrailResult> EvaluateAsync(
        GuardrailContext context,
        CancellationToken cancellationToken = default)
    {
        if (_classifier.Evaluate(context.Text, cancellationToken, out var verdict) is { } settled)
            return ValueTask.FromResult(settled);

        var score = verdict.Score;
        var reason = verdict.IsWindowed
            ? $"Defender classifier detected potential prompt injection (main: {score.Main:P1}, aux: {score.Aux:P1}; {WindowedClassification.DescribeWindow(verdict)})."
            : $"Defender classifier detected potential prompt injection (main: {score.Main:P1}, aux: {score.Aux:P1}).";
        var result = GuardrailResult.Blocked(reason, GuardrailSeverity.Critical);

        if (_options.IncludeConfidence)
        {
            var metadata = new Dictionary<string, object>
            {
                ["mainScore"] = score.Main,
                ["auxScore"] = score.Aux,
                ["model"] = ModelName,
                ["mainThreshold"] = _options.MainThreshold,
                ["auxThreshold"] = _options.AuxThreshold,
                ["temperatureT"] = _options.TemperatureT
            };
            if (verdict.IsWindowed)
                WindowedClassification.AddWindowMetadata(metadata, verdict);

            result = result with { Metadata = metadata };
        }

        return ValueTask.FromResult(result);
    }

    /// <summary>
    /// Releases this rule's reference to the pooled ONNX inference session. The session is shared
    /// process-wide and freed when its last holder releases it, so the reference is released exactly
    /// once: calling this again, from any thread, does nothing. An evaluation still running when this
    /// is called finishes normally, and the reference is released when it does; evaluations started
    /// afterwards throw <see cref="ObjectDisposedException"/>.
    /// </summary>
    public void Dispose() => _classifier.Dispose();

    private static void Validate(DefenderPromptInjectionOptions options)
    {
        OptionValidation.RequireProbability(options.MainThreshold, nameof(options.MainThreshold), nameof(options));
        OptionValidation.RequireProbability(options.AuxThreshold, nameof(options.AuxThreshold), nameof(options));
        if (!float.IsFinite(options.TemperatureT) || options.TemperatureT <= 0f)
            throw new ArgumentOutOfRangeException(nameof(options), options.TemperatureT, "TemperatureT must be a positive finite number.");
        OptionValidation.RequireMaxTokenLength(options.MaxTokenLength, SpecialTokenCount, nameof(options));
        WindowedClassification.ValidateWindowOptions(
            options.WindowSize, options.WindowOverlap, options.MaxWindows, nameof(options));
        OptionValidation.RequireErrorBehavior(options.OnError, nameof(options));
    }

    private static string ResolveModelPath(string? customPath, string fileName)
    {
        if (!string.IsNullOrWhiteSpace(customPath))
        {
            var fullPath = Path.GetFullPath(customPath);
            if (!File.Exists(fullPath))
                throw new FileNotFoundException($"Model file not found at '{fullPath}'.", fullPath);
            return fullPath;
        }

        // Look for bundled model next to the assembly
        var assemblyDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)
            ?? AppContext.BaseDirectory;
        var bundledPath = Path.Combine(assemblyDir, "defender-model", fileName);
        if (File.Exists(bundledPath))
            return bundledPath;

        throw new FileNotFoundException(
            $"Bundled Defender model file '{fileName}' not found at '{bundledPath}'. " +
            "Ensure the AgentGuard.Onnx NuGet package is correctly installed, or provide a custom path via options.",
            bundledPath);
    }
}
