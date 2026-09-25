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
/// is. Shorter input is classified in a single call.
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

    private readonly DefenderModelSession? _session;
    private readonly Func<string, DefenderScore> _classify;
    private readonly TextWindowSplitter _splitter;
    private readonly DefenderPromptInjectionOptions _options;
    private bool _disposed;

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
    public DefenderPromptInjectionRule(DefenderPromptInjectionOptions? options = null)
    {
        _options = options ?? new DefenderPromptInjectionOptions();

        if (_options.MainThreshold is < 0f or > 1f)
            throw new ArgumentOutOfRangeException(nameof(options), "MainThreshold must be between 0.0 and 1.0.");
        if (_options.AuxThreshold is < 0f or > 1f)
            throw new ArgumentOutOfRangeException(nameof(options), "AuxThreshold must be between 0.0 and 1.0.");
        if (_options.TemperatureT <= 0f || !float.IsFinite(_options.TemperatureT))
            throw new ArgumentOutOfRangeException(nameof(options), "TemperatureT must be a positive finite number.");
        WindowedClassification.ValidateWindowOptions(
            _options.WindowSize, _options.WindowOverlap, _options.MaxWindows, nameof(options));

        var modelPath = ResolveModelPath(_options.ModelPath, "model_quantized.onnx");
        var vocabPath = ResolveModelPath(_options.VocabPath, "vocab.txt");

        // counts tokens exactly like the session's own tokenizer (same vocab and options), so that
        // input which fits in one window is recognised as such and classified in a single call
        var tokenizer = BertTokenizer.Create(vocabPath, new BertOptions { LowerCaseBeforeTokenization = true });
        _splitter = WindowedClassification.CreateSplitter(
            text => tokenizer.CountTokens(text),
            _options.MaxTokenLength - SpecialTokenCount,
            _options.WindowSize,
            _options.WindowOverlap,
            nameof(options));

        _session = DefenderModelSession.Acquire(modelPath, vocabPath, _options.MaxTokenLength, _options.TemperatureT);
        _classify = _session.Classify;
    }

    /// <summary>
    /// Internal constructor for testing - classifies with <paramref name="classify"/> and counts tokens
    /// with <paramref name="countTokens"/> instead of loading the model.
    /// </summary>
    internal DefenderPromptInjectionRule(
        Func<string, DefenderScore> classify, TokenCounter countTokens, DefenderPromptInjectionOptions options)
    {
        _options = options;
        _classify = classify;
        WindowedClassification.ValidateWindowOptions(
            options.WindowSize, options.WindowOverlap, options.MaxWindows, nameof(options));
        _splitter = WindowedClassification.CreateSplitter(
            countTokens, options.MaxTokenLength - SpecialTokenCount, options.WindowSize, options.WindowOverlap, nameof(options));
    }

    /// <summary>
    /// The multi-head decision rule: block when the main score clears its threshold and the aux
    /// score does not reach the veto threshold. A high aux score (directive aimed at a human reader)
    /// vetoes the block.
    /// </summary>
    internal static bool ShouldBlock(DefenderScore score, float mainThreshold, float auxThreshold) =>
        score.Main >= mainThreshold && score.Aux < auxThreshold;

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
                "Defender", nameof(DefenderPromptInjectionOptions), _options.MaxWindows));
        }

        var verdict = WindowedClassification.Classify(
            context.Text,
            windows,
            _classify,
            score => ShouldBlock(score, _options.MainThreshold, _options.AuxThreshold),
            score => score.Main,
            cancellationToken);

        if (!verdict.IsBlocked)
            return ValueTask.FromResult(GuardrailResult.Passed());

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

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;
        _session?.Dispose();
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
