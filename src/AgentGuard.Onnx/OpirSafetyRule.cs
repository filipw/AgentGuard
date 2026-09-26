using System.Text.Json;
using AgentGuard.Core.Abstractions;
using Kyoto;

namespace AgentGuard.Onnx;

/// <summary>
/// ONNX-based, offline, multilingual content-safety classifier using the Opir-multilang model
/// (<see href="https://huggingface.co/knowledgator/opir-multitask-multilang-v1.0">knowledgator/opir-multitask-multilang-v1.0</see>,
/// GLiClass uni-encoder over mDeBERTa-v3-base, Apache-2.0). Runs fully offline. Order 50 - the
/// content-safety lane, alongside <c>ContentSafetyRule</c>.
/// <para>
/// Scores each input against a frozen harm taxonomy (toxicity, hate speech, violence, sexual
/// content, self-harm, harassment) and blocks when the strongest per-label probability reaches the
/// threshold. Its niche is <b>non-English</b> content safety: the bundled Defender classifier is
/// English-only (~0% recall off-English) and cloud content-safety APIs are per-call and PII-bound,
/// so this fills an offline multilingual gap rather than replacing them. See
/// the Opir evaluation in the Kyoto repo for measured recall/FPR across de/es/ru/ar/zh/hi.
/// </para>
/// <para>
/// Input longer than <see cref="OpirSafetyOptions.WindowSize"/> tokens is classified in overlapping
/// windows so that no part of it goes unclassified; the input is blocked when any window is. Shorter
/// input is classified in a single call.
/// </para>
/// <para>
/// The model must be downloaded separately - see <c>eng/MODELS.md</c>. The official
/// repo ships only PyTorch weights, so AgentGuard distributes a frozen-taxonomy ONNX export.
/// </para>
/// </summary>
public sealed class OpirSafetyRule : IGuardrailRule, IDisposable
{
    private const string ModelName = "opir-multilang-mdeberta-v3";

    // the session surrounds the text with at least a one-token label prefix and a trailing [SEP]
    private const int MinSpecialTokenCount = 2;

    private readonly IDisposable? _session;
    private readonly Func<string, OpirScore> _classify;
    private readonly IReadOnlyList<string> _labels;
    private readonly TextWindowSplitter _splitter;
    private readonly OpirSafetyOptions _options;
    private int _disposed;

    /// <inheritdoc />
    public string Name => "opir-content-safety";

    /// <inheritdoc />
    public GuardrailPhase Phase => GuardrailPhase.Input;

    /// <inheritdoc />
    public int Order => 50;

    /// <summary>
    /// Creates a new Opir content-safety rule. Loads (or reuses a pooled) ONNX session, the
    /// mDeBERTa SentencePiece tokenizer, and the frozen-taxonomy prefix from disk.
    /// </summary>
    /// <param name="options">Configuration including model, tokenizer, and prefix file paths.</param>
    /// <exception cref="ArgumentException">Thrown when a required path is missing.</exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when <see cref="OpirSafetyOptions.Threshold"/> is NaN or outside 0.0-1.0,
    /// <see cref="OpirSafetyOptions.MaxTokenLength"/> leaves no room for input tokens after the label
    /// prefix, or the window settings are invalid.
    /// </exception>
    /// <exception cref="FileNotFoundException">Thrown when a configured file does not exist.</exception>
    public OpirSafetyRule(OpirSafetyOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        Validate(options);

        var modelPath = OnnxFileValidation.RequireFile(options.ModelPath, nameof(options.ModelPath), "Opir ONNX model");
        var tokenizerPath = OnnxFileValidation.RequireFile(options.TokenizerPath, nameof(options.TokenizerPath), "mDeBERTa SentencePiece tokenizer");
        var prefixPath = OnnxFileValidation.RequireFile(options.PrefixPath, nameof(options.PrefixPath), "Opir prefix.json");

        _options = options;

        // counts tokens exactly like the session's own tokenizer (content ids only, no BOS/EOS), so that
        // input which fits in one window is recognised as such and classified in a single call
        var tokenizer = SentencePieceContentTokenizer.Load(tokenizerPath);

        _splitter = WindowedClassification.CreateSplitter(
            WindowedClassification.CountContentTokens(tokenizer),
            TextTokenBudget(options.MaxTokenLength, ReadPrefixTokenCount(prefixPath)),
            options.WindowSize,
            options.WindowOverlap,
            nameof(options));

        var session = OpirModelSession.Acquire(modelPath, tokenizerPath, prefixPath, options.MaxTokenLength);
        _session = session;
        _classify = session.Classify;
        _labels = session.Labels;
    }

    /// <summary>
    /// Internal constructor for testing - classifies with <paramref name="classify"/> and counts tokens
    /// with <paramref name="countTokens"/> instead of loading the model. <paramref name="labels"/> are
    /// the harm labels the scores are aligned with; <paramref name="prefixTokenCount"/> stands in for
    /// the length of the frozen label prefix. <paramref name="session"/>, when given, stands in for the
    /// pooled session and is released by <see cref="Dispose"/>.
    /// </summary>
    internal OpirSafetyRule(
        Func<string, OpirScore> classify,
        IReadOnlyList<string> labels,
        TokenCounter countTokens,
        int prefixTokenCount,
        OpirSafetyOptions options,
        IDisposable? session = null)
    {
        Validate(options);
        _options = options;
        _classify = classify;
        _labels = labels;
        _session = session;
        _splitter = WindowedClassification.CreateSplitter(
            countTokens, TextTokenBudget(options.MaxTokenLength, prefixTokenCount), options.WindowSize, options.WindowOverlap, nameof(options));
    }

    /// <inheritdoc />
    /// <exception cref="ObjectDisposedException">Thrown when the rule has been disposed.</exception>
    public ValueTask<GuardrailResult> EvaluateAsync(
        GuardrailContext context,
        CancellationToken cancellationToken = default)
    {
        // a disposed rule no longer holds a reference to the pooled session, which may already be freed
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);

        if (string.IsNullOrWhiteSpace(context.Text))
            return ValueTask.FromResult(GuardrailResult.Passed());

        if (!_splitter.TrySplit(context.Text, _options.MaxWindows, out var windows))
        {
            return ValueTask.FromResult(WindowedClassification.InputTooLong(
                "Opir content-safety", nameof(OpirSafetyOptions), _options.MaxWindows));
        }

        var verdict = WindowedClassification.Classify(
            context.Text,
            windows,
            _classify,
            score => score.MaxProbability >= _options.Threshold,
            score => score.MaxProbability,
            cancellationToken);

        if (!verdict.IsBlocked)
            return ValueTask.FromResult(GuardrailResult.Passed());

        var score = verdict.Score;
        var reason = verdict.IsWindowed
            ? $"Opir content-safety classifier flagged '{score.MaxLabel}' (confidence: {score.MaxProbability:P1}; {WindowedClassification.DescribeWindow(verdict)})."
            : $"Opir content-safety classifier flagged '{score.MaxLabel}' (confidence: {score.MaxProbability:P1}).";
        var result = GuardrailResult.Blocked(reason, GuardrailSeverity.High);

        if (_options.IncludeConfidence)
        {
            var perLabel = new Dictionary<string, object>(_labels.Count);
            for (var i = 0; i < _labels.Count; i++)
                perLabel[_labels[i]] = score.LabelProbabilities[i];

            var metadata = new Dictionary<string, object>
            {
                ["label"] = score.MaxLabel,
                ["confidence"] = score.MaxProbability,
                ["scores"] = perLabel,
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
    /// Releases this rule's reference to the pooled ONNX inference session. The session is shared
    /// process-wide and freed when its last holder releases it, so the reference is released exactly
    /// once: calling this again, from any thread, does nothing.
    /// </summary>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
            _session?.Dispose();
    }

    private static void Validate(OpirSafetyOptions options)
    {
        OptionValidation.RequireProbability(options.Threshold, nameof(options.Threshold), nameof(options));
        OptionValidation.RequireMaxTokenLength(options.MaxTokenLength, MinSpecialTokenCount, nameof(options));
        WindowedClassification.ValidateWindowOptions(
            options.WindowSize, options.WindowOverlap, options.MaxWindows, nameof(options));
    }

    // text tokens the session classifies without truncating: the rest after the label prefix and [SEP]
    private static int TextTokenBudget(int maxTokenLength, int prefixTokenCount) =>
        maxTokenLength - prefixTokenCount - 1;

    private static int ReadPrefixTokenCount(string prefixPath)
    {
        using var stream = File.OpenRead(prefixPath);
        using var document = JsonDocument.Parse(stream);
        return document.RootElement.GetProperty("prefix_ids").GetArrayLength();
    }
}
