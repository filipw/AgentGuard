namespace AgentGuard.RemoteClassifier;

/// <summary>
/// Splits text that is longer than a classifier takes in one request into overlapping windows that
/// each fit, so the whole text is classified instead of only the part the model reads.
/// </summary>
/// <remarks>
/// Lengths are counted in UTF-16 code units. A window ends at whitespace when there is some shortly
/// before the limit, otherwise at the limit itself, moved back one if it would split a surrogate
/// pair. Consecutive windows share at least the requested overlap, so a span up to that long lies
/// whole inside at least one window.
/// </remarks>
internal static class TextWindows
{
    /// <summary>
    /// The windows of <paramref name="text"/>, each at most <paramref name="maxLength"/> code units
    /// and overlapping the previous one by at least <paramref name="overlap"/>, leaving out those that
    /// are only whitespace. Text that already fits comes back unchanged as the only window.
    /// </summary>
    public static List<string> Split(string text, int maxLength, int overlap)
    {
        ArgumentNullException.ThrowIfNull(text);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxLength, 1);
        ArgumentOutOfRangeException.ThrowIfNegative(overlap);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(overlap, maxLength / 2);

        if (text.Length <= maxLength)
            return [text];

        // how far back from the limit a window may end to land on whitespace
        var slack = Math.Min(overlap / 2, maxLength / 8);

        var windows = new List<string>();
        var start = 0;
        while (text.Length - start > maxLength)
        {
            var end = FindEnd(text, start, start + maxLength, slack);
            Add(windows, text, start, end);

            // the next window starts inside this one; when the overlap would leave no progress
            // (a window shortened to keep a surrogate pair whole), it starts where this one ended
            var next = WithoutSplittingAPair(text, end - overlap);
            start = next > start ? next : end;
        }

        Add(windows, text, start, text.Length);
        return windows;
    }

    private static void Add(List<string> windows, string text, int start, int end)
    {
        var window = text.AsSpan(start, end - start);
        if (!window.IsWhiteSpace())
            windows.Add(window.ToString());
    }

    // the latest cut in (limit - slack, limit] that falls right after whitespace; without one, the
    // limit itself, moved back one if it would split a surrogate pair
    private static int FindEnd(string text, int start, int limit, int slack)
    {
        for (var cut = limit; cut > limit - slack; cut--)
        {
            if (char.IsWhiteSpace(text[cut - 1]))
                return cut;
        }

        var end = WithoutSplittingAPair(text, limit);

        // a one-character window cannot hold a pair; split it rather than stand still
        return end > start ? end : limit;
    }

    private static int WithoutSplittingAPair(string text, int index) =>
        index > 0 && index < text.Length && char.IsLowSurrogate(text[index]) && char.IsHighSurrogate(text[index - 1])
            ? index - 1
            : index;
}
