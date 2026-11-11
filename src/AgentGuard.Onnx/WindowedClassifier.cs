using AgentGuard.Core.Abstractions;

namespace AgentGuard.Onnx;

/// <summary>
/// The evaluation steps the ONNX classifier rules share: holding the inference session for the
/// duration of an evaluation, making the input safe to tokenize, classifying it window by window, and
/// turning a failure of the tokenizer or the model into an error result.
/// </summary>
/// <typeparam name="TScore">The classifier's score type.</typeparam>
internal sealed class WindowedClassifier<TScore> : IDisposable
{
    private readonly SessionLifetime _lifetime;
    private readonly string _ruleName;
    private readonly string _classifierName;
    private readonly string _optionsTypeName;
    private readonly Func<string, TScore> _classify;
    private readonly Func<TScore, bool> _isBlocked;
    private readonly Func<TScore, float> _rank;
    private readonly TextWindowSplitter _splitter;
    private readonly LongWordBreaker? _wordBreaker;
    private readonly bool _lineBreaksAsSpaces;
    private readonly int _maxWindows;
    private readonly ErrorBehavior _onError;

    /// <summary>Creates the classifier for one rule.</summary>
    /// <param name="rule">The owning rule, named in error results and in the exception thrown after disposal.</param>
    /// <param name="classifierName">Human-readable classifier name for the too-long block reason.</param>
    /// <param name="optionsTypeName">Name of the options type that holds <c>MaxWindows</c>.</param>
    /// <param name="session">The inference session to release on disposal, if the rule owns one.</param>
    /// <param name="classify">Classifies one piece of text.</param>
    /// <param name="isBlocked">Whether a score blocks.</param>
    /// <param name="rank">Orders scores by severity; the highest-ranked blocking window is reported.</param>
    /// <param name="splitter">Splits input into windows the session encodes whole.</param>
    /// <param name="maxWindows">Maximum number of windows per input (0 = no limit).</param>
    /// <param name="onError">How a failure to classify is handled.</param>
    /// <param name="wordBreaker">Breaks words the tokenizer would not encode, when it has a per-word limit.</param>
    /// <param name="lineBreaksAsSpaces">
    /// Whether line breaks and tabs are handed to the tokenizer as spaces, for a tokenizer that would drop
    /// them and join the words on either side (see <see cref="ClassifierInput.LineBreaksToSpaces"/>).
    /// </param>
    public WindowedClassifier(
        IGuardrailRule rule,
        string classifierName,
        string optionsTypeName,
        IDisposable? session,
        Func<string, TScore> classify,
        Func<TScore, bool> isBlocked,
        Func<TScore, float> rank,
        TextWindowSplitter splitter,
        int maxWindows,
        ErrorBehavior onError,
        LongWordBreaker? wordBreaker = null,
        bool lineBreaksAsSpaces = false)
    {
        _lineBreaksAsSpaces = lineBreaksAsSpaces;
        _lifetime = new SessionLifetime(session, rule.GetType());
        _ruleName = rule.Name;
        _classifierName = classifierName;
        _optionsTypeName = optionsTypeName;
        _classify = classify;
        _isBlocked = isBlocked;
        _rank = rank;
        _splitter = splitter;
        _maxWindows = maxWindows;
        _onError = onError;
        _wordBreaker = wordBreaker;
    }

    /// <summary>
    /// Classifies <paramref name="text"/> and settles every outcome except a block: empty and clean
    /// input passes, input needing too many windows is blocked as too long, and a tokenizer or model
    /// failure becomes an error result shaped by the rule's <see cref="ErrorBehavior"/>.
    /// </summary>
    /// <param name="text">The input text.</param>
    /// <param name="cancellationToken">Checked between windows when there is more than one.</param>
    /// <param name="blocked">The blocking verdict, positioned in <paramref name="text"/>, when the result is null.</param>
    /// <returns>The settled result, or null when the input is blocked and the rule builds the result from <paramref name="blocked"/>.</returns>
    /// <exception cref="ObjectDisposedException">Thrown when the rule has been disposed.</exception>
    /// <exception cref="OperationCanceledException">Thrown when <paramref name="cancellationToken"/> is cancelled.</exception>
    public GuardrailResult? Evaluate(string? text, CancellationToken cancellationToken, out WindowedVerdict<TScore> blocked)
    {
        blocked = default;

        // the session must outlive the evaluation: a concurrent Dispose waits for this to be released
        using var usage = _lifetime.Enter();

        if (string.IsNullOrWhiteSpace(text))
            return GuardrailResult.Passed();

        try
        {
            var wellFormed = ClassifierInput.ReplaceUnpairedSurrogates(text);
            if (_lineBreaksAsSpaces)
                wellFormed = ClassifierInput.LineBreaksToSpaces(wellFormed);
            var prepared = _wordBreaker?.Break(wellFormed) ?? new PreparedText(wellFormed);

            if (!_splitter.TrySplit(prepared.Text, _maxWindows, out var windows))
                return WindowedClassification.InputTooLong(_classifierName, _optionsTypeName, _maxWindows);

            var verdict = WindowedClassification.Classify(prepared.Text, windows, _classify, _isBlocked, _rank, cancellationToken);
            if (!verdict.IsBlocked)
                return GuardrailResult.Passed();

            blocked = verdict with { Window = prepared.ToInputWindow(verdict.Window) };
            return null;
        }
        catch (Exception ex) when (ex is not (OperationCanceledException or ObjectDisposedException))
        {
            // an input the tokenizer or the model cannot process must not take the caller down with
            // it, nor slip through unclassified unless the rule is configured to let it
            return GuardrailResult.Error(_ruleName, _onError, $"{ex.GetType().Name}: {ex.Message}");
        }
    }

    /// <summary>
    /// Releases the inference session once no evaluation is using it. Calling this again, from any
    /// thread, does nothing.
    /// </summary>
    public void Dispose() => _lifetime.Dispose();
}
