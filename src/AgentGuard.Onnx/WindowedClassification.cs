using AgentGuard.Core.Abstractions;
using Microsoft.ML.Tokenizers;

namespace AgentGuard.Onnx;

/// <summary>
/// The verdict of classifying an input window by window: the scores of the worst window (the
/// highest-scoring blocking window, or the highest-scoring window when none blocks) and where it is.
/// </summary>
/// <typeparam name="TScore">The classifier's score type.</typeparam>
/// <param name="Score">The worst window's score.</param>
/// <param name="IsBlocked">Whether any window was blocked.</param>
/// <param name="WindowIndex">Zero-based index of the worst window.</param>
/// <param name="WindowCount">Number of windows classified.</param>
/// <param name="Window">Character range of the worst window within the input.</param>
internal readonly record struct WindowedVerdict<TScore>(
    TScore Score, bool IsBlocked, int WindowIndex, int WindowCount, TextWindow Window)
{
    /// <summary>Whether the input was split into more than one window.</summary>
    public bool IsWindowed => WindowCount > 1;
}

/// <summary>
/// Shared windowed-classification logic for the ONNX classifier rules: runs a classifier over every
/// window of an input and builds the common result pieces (window metadata, the too-long block).
/// </summary>
internal static class WindowedClassification
{
    /// <summary>
    /// Classifies <paramref name="text"/> window by window. A window spanning the whole text is
    /// classified by passing the original text unchanged, so input that fits in one window gets
    /// exactly the pre-windowing call.
    /// </summary>
    /// <param name="text">The input text.</param>
    /// <param name="windows">The windows produced by <see cref="TextWindowSplitter"/> for the text (at least one).</param>
    /// <param name="classify">Classifies one piece of text.</param>
    /// <param name="isBlocked">Whether a score blocks.</param>
    /// <param name="rank">Orders scores by severity; the highest-ranked blocking window is reported.</param>
    /// <param name="cancellationToken">Checked between windows when there is more than one.</param>
    public static WindowedVerdict<TScore> Classify<TScore>(
        string text,
        IReadOnlyList<TextWindow> windows,
        Func<string, TScore> classify,
        Func<TScore, bool> isBlocked,
        Func<TScore, float> rank,
        CancellationToken cancellationToken)
    {
        ArgumentOutOfRangeException.ThrowIfZero(windows.Count);

        WindowedVerdict<TScore>? worst = null;
        for (var i = 0; i < windows.Count; i++)
        {
            if (windows.Count > 1)
                cancellationToken.ThrowIfCancellationRequested();

            var window = windows[i];
            var piece = window.Start == 0 && window.Length == text.Length ? text : text.Substring(window.Start, window.Length);
            var score = classify(piece);
            var blocked = isBlocked(score);

            if (worst is not { } current
                || (blocked && !current.IsBlocked)
                || (blocked == current.IsBlocked && rank(score) > rank(current.Score)))
            {
                worst = new WindowedVerdict<TScore>(score, blocked, i, windows.Count, window);
            }
        }

        return worst!.Value;
    }

    /// <summary>
    /// Adds the location of the reported window to block metadata. Only called for windowed input, so
    /// the metadata of input that fits in a single window is unchanged.
    /// </summary>
    public static void AddWindowMetadata<TScore>(Dictionary<string, object> metadata, WindowedVerdict<TScore> verdict)
    {
        metadata["windowIndex"] = verdict.WindowIndex;
        metadata["windowCount"] = verdict.WindowCount;
        metadata["windowStart"] = verdict.Window.Start;
        metadata["windowLength"] = verdict.Window.Length;
    }

    /// <summary>Describes where in a windowed input the reported window is, for block reasons.</summary>
    public static string DescribeWindow<TScore>(WindowedVerdict<TScore> verdict) =>
        $"window {verdict.WindowIndex + 1} of {verdict.WindowCount}, characters {verdict.Window.Start}-{verdict.Window.End}";

    /// <summary>
    /// The result for input that needs more windows than the configured limit. It is blocked rather
    /// than passed, because passing would leave most of the input unclassified.
    /// </summary>
    /// <param name="classifierName">Human-readable classifier name for the reason.</param>
    /// <param name="optionsTypeName">Name of the options type that holds <c>MaxWindows</c>.</param>
    /// <param name="maxWindows">The configured limit.</param>
    public static GuardrailResult InputTooLong(string classifierName, string optionsTypeName, int maxWindows) =>
        GuardrailResult.Blocked(
            $"Input is too long for the {classifierName} classifier to scan completely (it needs more than " +
            $"{maxWindows} windows). Shorten the input or raise {optionsTypeName}.MaxWindows (0 = no limit).",
            GuardrailSeverity.Medium) with
        {
            Metadata = new Dictionary<string, object>
            {
                ["inputTooLong"] = true,
                ["maxWindows"] = maxWindows
            }
        };

    /// <summary>Counts content tokens with a SentencePiece tokenizer, leaving out any BOS/EOS it is configured to add.</summary>
    public static TokenCounter CountContentTokens(SentencePieceTokenizer tokenizer) =>
        text => tokenizer.CountTokens(text, addBeginningOfSentence: false, addEndOfSentence: false);

    /// <summary>
    /// Content tokens a Kyoto <c>OnnxModelSession</c> classifies without truncating: its
    /// <paramref name="maxTokenLength"/> minus the <c>[CLS]</c>/<c>[SEP]</c> it adds and minus any
    /// BOS/EOS the tokenizer itself emits.
    /// </summary>
    public static int OnnxSessionContentBudget(SentencePieceTokenizer tokenizer, int maxTokenLength) =>
        maxTokenLength - 2
        - (tokenizer.AddBeginningOfSentence ? 1 : 0)
        - (tokenizer.AddEndOfSentence ? 1 : 0);

    /// <summary>
    /// Validates the windowing settings that do not depend on the model. Called before anything is
    /// loaded so that a misconfiguration fails fast.
    /// </summary>
    /// <param name="windowSize">Configured window size in tokens.</param>
    /// <param name="windowOverlap">Configured window overlap in tokens.</param>
    /// <param name="maxWindows">Configured window limit (0 = no limit).</param>
    /// <param name="paramName">The caller's options parameter name, for exceptions.</param>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when a setting is out of range.</exception>
    public static void ValidateWindowOptions(int windowSize, int windowOverlap, int maxWindows, string paramName)
    {
        if (windowSize < 1)
            throw new ArgumentOutOfRangeException(paramName, "WindowSize must be at least 1.");
        if (windowOverlap < 0)
            throw new ArgumentOutOfRangeException(paramName, "WindowOverlap must not be negative.");
        if (windowOverlap >= windowSize)
            throw new ArgumentOutOfRangeException(paramName, $"WindowOverlap ({windowOverlap}) must be smaller than WindowSize ({windowSize}).");
        if (maxWindows < 0)
            throw new ArgumentOutOfRangeException(paramName, "MaxWindows must not be negative (0 = no limit).");
    }

    /// <summary>
    /// Builds a splitter once the model's token budget is known, clamping the window size to what the
    /// model accepts without truncation.
    /// </summary>
    /// <param name="countTokens">Content-token counter matching the classifier's tokenizer.</param>
    /// <param name="modelTokenBudget">Content tokens the classifier session accepts without truncating.</param>
    /// <param name="windowSize">Configured window size in tokens.</param>
    /// <param name="windowOverlap">Configured window overlap in tokens.</param>
    /// <param name="paramName">The caller's options parameter name, for exceptions.</param>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when the budget leaves no room for the configured overlap.</exception>
    public static TextWindowSplitter CreateSplitter(
        TokenCounter countTokens, int modelTokenBudget, int windowSize, int windowOverlap, string paramName)
    {
        if (modelTokenBudget < 1)
            throw new ArgumentOutOfRangeException(paramName, "MaxTokenLength is too small to leave room for any input tokens.");

        var effectiveWindowSize = Math.Min(windowSize, modelTokenBudget);
        if (windowOverlap >= effectiveWindowSize)
        {
            throw new ArgumentOutOfRangeException(
                paramName,
                $"WindowOverlap ({windowOverlap}) must be smaller than the effective window size ({effectiveWindowSize} tokens: " +
                "WindowSize capped to what MaxTokenLength allows).");
        }

        return new TextWindowSplitter(countTokens, effectiveWindowSize, windowOverlap);
    }
}
