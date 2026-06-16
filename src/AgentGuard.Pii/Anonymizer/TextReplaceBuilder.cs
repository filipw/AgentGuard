namespace AgentGuard.Pii.Anonymizer;

/// <summary>
/// Rebuilds text by replacing spans from end to start, so that earlier offsets remain valid as later
/// ones are replaced.
/// </summary>
internal sealed class TextReplaceBuilder
{
    private readonly string _originalText;
    private readonly int _textLen;
    private int _lastReplacementIndex;

    public TextReplaceBuilder(string originalText)
    {
        _originalText = originalText;
        OutputText = originalText;
        _textLen = originalText.Length;
        _lastReplacementIndex = _textLen;
    }

    public string OutputText { get; private set; }

    public string GetTextInPosition(int start, int end)
    {
        if (_textLen < start || end > _textLen)
        {
            throw new ArgumentException($"Invalid analyzer result, start: {start} and end: {end}, while text length is only {_textLen}.");
        }

        return _originalText[start..end];
    }

    /// <summary>Replaces the span [start, end) with <paramref name="replacementText"/>, returning the index from the end.</summary>
    public int ReplaceTextGetInsertionIndex(string replacementText, int start, int end)
    {
        var endOfTextIndex = Math.Min(end, _lastReplacementIndex);
        _lastReplacementIndex = start;

        var beforeText = OutputText[..start];
        var afterText = OutputText[endOfTextIndex..];
        OutputText = beforeText + replacementText + afterText;

        return afterText.Length + replacementText.Length;
    }
}
