namespace AgentGuard.Onnx;

/// <summary>
/// Counts the content tokens a classifier would see for a piece of text, excluding the special
/// tokens (<c>[CLS]</c>, <c>[SEP]</c>, BOS/EOS, label prefixes) its session adds around every input.
/// </summary>
internal delegate int TokenCounter(ReadOnlySpan<char> text);

/// <summary>A contiguous character range of an input that is classified on its own.</summary>
/// <param name="Start">Index of the first character of the window.</param>
/// <param name="Length">Number of characters in the window.</param>
internal readonly record struct TextWindow(int Start, int Length)
{
    /// <summary>Index just past the last character of the window.</summary>
    public int End => Start + Length;
}

/// <summary>
/// Splits input that is longer than a classifier's window into overlapping, token-bounded windows
/// so that every part of the text is classified. Text that fits in one window comes back as a
/// single window covering the whole text, so short input is classified exactly as before.
/// </summary>
/// <remarks>
/// Windows are cut at whitespace so every window is a verbatim slice of the input. Runs of text
/// without whitespace that hold more than half the overlap in tokens (CJK text, minified code,
/// encoded blobs, long URLs) are cut into pieces of that size first, so the overlap between windows
/// is kept even inside them. Window token counts are estimated from per-word counts and then
/// verified against the real count of the window text, so a window never exceeds the window size
/// and is never truncated by the session. Consecutive windows share up to the overlap in tokens (in
/// whole words), which puts any run of words holding no more tokens than the overlap entirely inside
/// at least one window. The last window is pulled back to full size. Instances are immutable and
/// thread-safe.
/// </remarks>
internal sealed class TextWindowSplitter
{
    private readonly TokenCounter _countTokens;
    private readonly int _pieceTokens;

    /// <summary>Creates a splitter.</summary>
    /// <param name="countTokens">Content-token counter matching the classifier's tokenizer.</param>
    /// <param name="windowSize">Maximum number of content tokens per window.</param>
    /// <param name="windowOverlap">Number of tokens consecutive windows share. Must be smaller than <paramref name="windowSize"/>.</param>
    public TextWindowSplitter(TokenCounter countTokens, int windowSize, int windowOverlap)
    {
        ArgumentNullException.ThrowIfNull(countTokens);
        ArgumentOutOfRangeException.ThrowIfLessThan(windowSize, 1);
        ArgumentOutOfRangeException.ThrowIfNegative(windowOverlap);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(windowOverlap, windowSize);

        _countTokens = countTokens;
        WindowSize = windowSize;
        WindowOverlap = windowOverlap;

        // whitespace-free runs are cut into pieces small enough for the overlap to be honoured
        _pieceTokens = windowOverlap > 0 ? Math.Max(1, windowOverlap / 2) : windowSize;
    }

    /// <summary>Maximum number of content tokens per window.</summary>
    public int WindowSize { get; }

    /// <summary>Number of tokens consecutive windows share.</summary>
    public int WindowOverlap { get; }

    /// <summary>Splits <paramref name="text"/> into windows without a limit on their number.</summary>
    /// <param name="text">The input text.</param>
    /// <returns>The windows, in order. A single whole-text window when the text fits.</returns>
    public IReadOnlyList<TextWindow> Split(string text)
    {
        TrySplit(text, maxWindows: 0, out var windows);
        return windows;
    }

    /// <summary>
    /// Splits <paramref name="text"/> into windows, giving up early when it needs more than
    /// <paramref name="maxWindows"/> of them.
    /// </summary>
    /// <param name="text">The input text.</param>
    /// <param name="maxWindows">Maximum number of windows, or 0 for no limit.</param>
    /// <param name="windows">The windows, in order; empty when the limit is exceeded.</param>
    /// <returns><see langword="false"/> when the text needs more than <paramref name="maxWindows"/> windows.</returns>
    public bool TrySplit(string text, int maxWindows, out IReadOnlyList<TextWindow> windows)
    {
        ArgumentNullException.ThrowIfNull(text);
        ArgumentOutOfRangeException.ThrowIfNegative(maxWindows);

        var totalTokens = _countTokens(text);
        if (totalTokens <= WindowSize)
        {
            windows = [new TextWindow(0, text.Length)];
            return true;
        }

        // no window holds more than WindowSize tokens, so this many tokens cannot fit in the limit;
        // bail out before doing any per-word work
        if (maxWindows > 0 && totalTokens > (long)maxWindows * WindowSize)
        {
            windows = [];
            return false;
        }

        var segments = CollectSegments(text);
        var result = new List<TextWindow>();
        if (!BuildWindows(text, segments, maxWindows, result))
        {
            windows = [];
            return false;
        }

        windows = result;
        return true;
    }

    private bool BuildWindows(string text, List<Segment> segments, int maxWindows, List<TextWindow> result)
    {
        var count = segments.Count;
        if (count == 0)
        {
            result.Add(new TextWindow(0, text.Length));
            return true;
        }

        var prefix = new long[count + 1];
        for (var i = 0; i < count; i++)
            prefix[i + 1] = prefix[i] + segments[i].Tokens;

        long Tokens(int from, int to) => prefix[to] - prefix[from];

        var start = 0;
        while (true)
        {
            // the longest run of whole segments from start that fits the window
            var end = start + 1;
            while (end < count && Tokens(start, end + 1) <= WindowSize)
                end++;

            // per-segment counts can undercount (e.g. whitespace a tokenizer turns into tokens), so
            // check the real count and give segments back until the window truly fits
            while (end - start > 1 && CountTokens(text, segments, start, end) > WindowSize)
                end--;

            if (end == count)
            {
                // last window: pull its start back so it is full-size rather than a short tail
                var fullStart = start;
                while (fullStart > 0 && Tokens(fullStart - 1, count) <= WindowSize)
                    fullStart--;
                if (fullStart < start && CountTokens(text, segments, fullStart, count) <= WindowSize)
                    start = fullStart;

                result.Add(ToWindow(segments, start, count));
                return true;
            }

            result.Add(ToWindow(segments, start, end));
            if (maxWindows > 0 && result.Count >= maxWindows)
                return false;

            // step back so the next window repeats roughly WindowOverlap tokens of this one
            var next = end;
            while (next - 1 > start && Tokens(next - 1, end) <= WindowOverlap)
                next--;
            start = next;
        }
    }

    private List<Segment> CollectSegments(string text)
    {
        var segments = new List<Segment>();
        var i = 0;
        while (i < text.Length)
        {
            while (i < text.Length && char.IsWhiteSpace(text[i]))
                i++;
            if (i == text.Length)
                break;

            var start = i;
            while (i < text.Length && !char.IsWhiteSpace(text[i]))
                i++;

            var tokens = _countTokens(text.AsSpan(start, i - start));
            if (tokens <= _pieceTokens)
                segments.Add(new Segment(start, i, tokens));
            else
                AddPieces(text, start, i, tokens, segments);
        }

        return segments;
    }

    private void AddPieces(string text, int start, int end, int tokens, List<Segment> segments)
    {
        // a long whitespace-free run: cut it into pieces of about _pieceTokens tokens, sized from the
        // run's average token density and verified against the real count
        var targetLength = (int)Math.Max(1, (long)(end - start) * _pieceTokens / tokens);
        var position = start;
        while (position < end)
        {
            var length = Math.Min(targetLength, end - position);
            while (true)
            {
                length = AvoidSplittingSurrogatePair(text, position, length, end);
                var pieceTokens = _countTokens(text.AsSpan(position, length));
                if (pieceTokens <= _pieceTokens || length <= 2)
                {
                    segments.Add(new Segment(position, position + length, pieceTokens));
                    break;
                }

                length = Math.Max(1, (int)((long)length * _pieceTokens / pieceTokens) - 1);
            }

            position += length;
        }
    }

    private static int AvoidSplittingSurrogatePair(string text, int position, int length, int end)
    {
        var last = position + length - 1;
        if (position + length < end && char.IsHighSurrogate(text[last]))
            return length > 1 ? length - 1 : Math.Min(2, end - position);
        return length;
    }

    private int CountTokens(string text, List<Segment> segments, int from, int to)
    {
        var start = segments[from].Start;
        return _countTokens(text.AsSpan(start, segments[to - 1].End - start));
    }

    private static TextWindow ToWindow(List<Segment> segments, int from, int to)
    {
        var start = segments[from].Start;
        return new TextWindow(start, segments[to - 1].End - start);
    }

    private readonly record struct Segment(int Start, int End, int Tokens);
}
