using System.Reflection;
using AgentGuard.Core.Abstractions;

namespace AgentGuard.Onnx;

/// <summary>
/// Prompt injection classifier powered by the StackOne Defender multi-head MiniLM-L6 ONNX model
/// (minilm-multihead-v5). Runs fully offline with fast inference (~8 ms per sample). Order 11 -
/// runs before DeBERTa (order 12).
/// <para>
/// The model emits two temperature-calibrated scores: a main injection score and an auxiliary
/// "directed at a human reader" score. Input is blocked when
/// <c>main &gt;= MainThreshold AND aux &lt; AuxThreshold</c>; a high aux score vetoes the block.
/// This rescues imperative-but-benign phrasings (e.g. "show me my orders") that the single-head
/// model used to flag as false positives.
/// </para>
/// <para>
/// The model is bundled with this NuGet package - no separate download required.
/// Based on the <see href="https://github.com/StackOneHQ/defender">StackOne Defender</see> project (Apache 2.0 license).
/// </para>
/// </summary>
public sealed class DefenderPromptInjectionRule : IGuardrailRule, IDisposable
{
    private readonly DefenderModelSession _session;
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

        var modelPath = ResolveModelPath(_options.ModelPath, "model_quantized.onnx");
        var vocabPath = ResolveModelPath(_options.VocabPath, "vocab.txt");

        _session = DefenderModelSession.Acquire(modelPath, vocabPath, _options.MaxTokenLength, _options.TemperatureT);
    }

    /// <summary>
    /// Internal constructor for testing - accepts a pre-built session.
    /// </summary>
    internal DefenderPromptInjectionRule(DefenderModelSession session, DefenderPromptInjectionOptions options)
    {
        _session = session;
        _options = options;
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

        var score = _session.Classify(context.Text);

        if (ShouldBlock(score, _options.MainThreshold, _options.AuxThreshold))
        {
            var result = GuardrailResult.Blocked(
                $"Defender classifier detected potential prompt injection (main: {score.Main:P1}, aux: {score.Aux:P1}).",
                GuardrailSeverity.Critical);

            if (_options.IncludeConfidence)
            {
                result = result with
                {
                    Metadata = new Dictionary<string, object>
                    {
                        ["mainScore"] = score.Main,
                        ["auxScore"] = score.Aux,
                        ["model"] = "stackone-defender-minilm-multihead-v5",
                        ["mainThreshold"] = _options.MainThreshold,
                        ["auxThreshold"] = _options.AuxThreshold,
                        ["temperatureT"] = _options.TemperatureT
                    }
                };
            }

            return ValueTask.FromResult(result);
        }

        return ValueTask.FromResult(GuardrailResult.Passed());
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;
        _session.Dispose();
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
