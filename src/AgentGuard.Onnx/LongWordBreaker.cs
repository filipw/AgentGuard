namespace AgentGuard.Onnx;

/// <summary>
/// Tells whether a tokenizer encodes every word of a piece of text, rather than replacing a word that
/// exceeds its per-word length limit with a single unknown token.
/// </summary>
internal delegate bool WordVisibilityCheck(ReadOnlySpan<char> text);

/// <summary>
/// Text as it is given to a classifier: the input, possibly with separators added to it, and the way
/// back from positions in it to positions in the input.
/// </summary>
internal readonly struct PreparedText
{
    // indices in Text of the separators that are not in the input, ascending
    private readonly int[]? _addedSeparators;

    /// <summary>Wraps text and the positions of the separators added to it.</summary>
    /// <param name="text">The text to classify.</param>
    /// <param name="addedSeparators">Ascending indices in <paramref name="text"/> of added separators, or null for none.</param>
    public PreparedText(string text, int[]? addedSeparators = null)
    {
        Text = text;
        _addedSeparators = addedSeparators is { Length: > 0 } ? addedSeparators : null;
    }

    /// <summary>The text to classify.</summary>
    public string Text { get; }

    /// <summary>Number of separators added to the input.</summary>
    public int AddedSeparatorCount => _addedSeparators?.Length ?? 0;

    /// <summary>Converts a window of <see cref="Text"/> to the range of the input it covers.</summary>
    public TextWindow ToInputWindow(TextWindow window)
    {
        if (_addedSeparators is null)
            return window;

        var start = ToInputIndex(window.Start);
        return new TextWindow(start, ToInputIndex(window.End) - start);
    }

    private int ToInputIndex(int index)
    {
        var position = Array.BinarySearch(_addedSeparators!, index);
        var addedBefore = position >= 0 ? position : ~position;
        return index - addedBefore;
    }
}

/// <summary>
/// Breaks words that are too long for a tokenizer's per-word limit into pieces it encodes, by adding
/// a space between the pieces. Without this such a word reaches the model as one unknown token, and
/// whatever is written in it or glued to it goes unclassified.
/// </summary>
/// <remarks>
/// Only space-delimited runs holding a word over the limit are touched; all other text, including
/// long runs the tokenizer itself splits at punctuation, is left exactly as it is. Examining the text
/// one such run at a time relies on the tokenizer never joining text across a space. A run is cut at
/// the line breaks and tabs in it first, because a tokenizer that reads past those is what joins
/// short words into one that is too long, and then wherever a word still reaches the limit.
/// Instances are immutable and thread-safe.
/// </remarks>
internal sealed class LongWordBreaker
{
    private readonly WordVisibilityCheck _isVisible;
    private readonly int _probeLength;

    /// <summary>Creates a breaker.</summary>
    /// <param name="isVisible">Whether the tokenizer encodes every word of a piece of text.</param>
    /// <param name="probeLength">
    /// Length of the first piece tried when looking for the place to cut, typically the tokenizer's
    /// per-word limit.
    /// </param>
    public LongWordBreaker(WordVisibilityCheck isVisible, int probeLength)
    {
        ArgumentNullException.ThrowIfNull(isVisible);
        ArgumentOutOfRangeException.ThrowIfLessThan(probeLength, 1);

        _isVisible = isVisible;
        _probeLength = probeLength;
    }

    /// <summary>Adds a space wherever a word of <paramref name="text"/> has to be cut for the tokenizer to encode it.</summary>
    /// <param name="text">The input text. Must not contain unpaired surrogates.</param>
    /// <returns><paramref name="text"/> itself when no word is too long, otherwise a copy with the added spaces.</returns>
    public PreparedText Break(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        List<int>? cuts = null;
        var position = 0;
        while (position < text.Length)
        {
            var end = text.IndexOf(' ', position);
            if (end < 0)
                end = text.Length;

            if (end > position && !_isVisible(text.AsSpan(position, end - position)))
                AddCuts(text, position, end, cuts ??= []);

            position = end + 1;
        }

        return cuts is null ? new PreparedText(text) : InsertSpaces(text, cuts);
    }

    // records the input indices at which the run [start, end), which holds a word that is too long,
    // has to be cut
    private void AddCuts(string text, int start, int end, List<int> cuts)
    {
        var position = start;
        while (position < end)
        {
            while (position < end && char.IsWhiteSpace(text[position]))
                position++;
            if (position == end)
                return;

            // a line break or tab the tokenizer read past, joining the words around it into the long
            // one, is where the word is cut first
            if (position > start && char.IsWhiteSpace(text[position - 1]))
                cuts.Add(position);

            var wordEnd = position;
            while (wordEnd < end && !char.IsWhiteSpace(text[wordEnd]))
                wordEnd++;

            // what is still too long is cut wherever it reaches the limit
            while (true)
            {
                var run = text.AsSpan(position, wordEnd - position);
                var length = VisiblePrefixLength(run);
                position += length;
                if (length == run.Length)
                    break;

                cuts.Add(position);
            }
        }
    }

    // the length of the longest prefix of the run in which the tokenizer encodes every word
    private int VisiblePrefixLength(ReadOnlySpan<char> run)
    {
        // double the prefix until a word in it gets too long, then narrow down where that happens
        var visible = 0;
        int tooLong;
        var probe = Math.Min(_probeLength, run.Length);
        while (true)
        {
            var length = WholeCharacters(run, probe);
            if (!_isVisible(run[..length]))
            {
                tooLong = length;
                break;
            }

            visible = length;
            if (length == run.Length)
                return length;

            probe = (int)Math.Min(run.Length, (long)length * 2);
        }

        var low = visible;
        var high = tooLong - 1;
        while (low < high)
        {
            var middle = low + ((high - low + 1) / 2);
            var length = WholeCharacters(run, middle);
            if (length <= high && _isVisible(run[..length]))
                low = length;
            else
                high = middle - 1;
        }

        // a single character is always taken, so that cutting makes progress
        return Math.Max(low, WholeCharacters(run, 1));
    }

    // the length extended by one when it would otherwise end between the halves of a surrogate pair
    private static int WholeCharacters(ReadOnlySpan<char> run, int length) =>
        length < run.Length && char.IsHighSurrogate(run[length - 1]) && char.IsLowSurrogate(run[length])
            ? length + 1
            : length;

    private static PreparedText InsertSpaces(string text, List<int> cuts)
    {
        var added = new int[cuts.Count];
        var prepared = string.Create(text.Length + cuts.Count, (text, cuts, added), static (destination, state) =>
        {
            var (source, cutIndices, addedSeparators) = state;
            var copied = 0;
            var written = 0;
            for (var i = 0; i < cutIndices.Count; i++)
            {
                var cut = cutIndices[i];
                source.AsSpan(copied, cut - copied).CopyTo(destination[written..]);
                written += cut - copied;
                addedSeparators[i] = written;
                destination[written++] = ' ';
                copied = cut;
            }

            source.AsSpan(copied).CopyTo(destination[written..]);
        });

        return new PreparedText(prepared, added);
    }
}
