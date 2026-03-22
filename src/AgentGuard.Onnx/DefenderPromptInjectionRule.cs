using System.Reflection;
using AgentGuard.Core.Abstractions;

namespace AgentGuard.Onnx;

/// <summary>
/// Prompt injection classifier powered by the StackOne Defender fine-tuned MiniLM-L6-v2 ONNX model.
/// Runs fully offline with fast inference (~8 ms per sample). Order 11 - runs before DeBERTa (order 12).
/// <para>
/// The model is bundled with this NuGet package - no separate download required.
/// Based on the <see href="https://github.com/StackOneHQ/defender">StackOne Defender</see> project (Apache 2.0 license).
/// </para>
/// </summary>
public sealed class DefenderPromptInjectionRule : IGuardrailRule, IDisposable
{
    private readonly DefenderModelSession _session;
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
    public DefenderPromptInjectionRule(DefenderPromptInjectionOptions? options = null)
    {
        _options = options ?? new DefenderPromptInjectionOptions();

        if (_options.Threshold is < 0f or > 1f)
            throw new ArgumentOutOfRangeException(nameof(options), "Threshold must be between 0.0 and 1.0.");

        var modelPath = ResolveModelPath(_options.ModelPath, "model_quantized.onnx");
        var vocabPath = ResolveModelPath(_options.VocabPath, "vocab.txt");

        _session = new DefenderModelSession(modelPath, vocabPath, _options.MaxTokenLength);
    }

    /// <summary>
    /// Internal constructor for testing - accepts a pre-built session.
    /// </summary>
    internal DefenderPromptInjectionRule(DefenderModelSession session, DefenderPromptInjectionOptions options)
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

        var injectionProb = _session.Classify(context.Text);

        if (injectionProb >= _options.Threshold)
        {
            var result = GuardrailResult.Blocked(
                $"Defender classifier detected potential prompt injection (confidence: {injectionProb:P1}).",
                GuardrailSeverity.Critical);

            if (_options.IncludeConfidence)
            {
                result = result with
                {
                    Metadata = new Dictionary<string, object>
                    {
                        ["confidence"] = injectionProb,
                        ["model"] = "stackone-defender-minilm-v2",
                        ["threshold"] = _options.Threshold
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
