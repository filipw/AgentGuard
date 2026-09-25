using System.Globalization;

namespace AgentGuard.Azure;

/// <summary>A window into a longer text, as a UTF-16 offset and length.</summary>
/// <param name="Start">Offset of the window's first code unit.</param>
/// <param name="Length">Number of code units in the window.</param>
internal readonly record struct TextWindow(int Start, int Length);

/// <summary>
/// Splits text that is over a service's per-request size limit into overlapping windows that each
/// fit under it, so oversized input is analyzed in parts instead of being rejected.
/// </summary>
/// <remarks>
/// Lengths are counted in UTF-16 code units. That count is never lower than the code point or text
/// element counts the Azure services measure, so a window that fits by this count fits by theirs.
/// A window ends at whitespace when there is some shortly before the limit (a line break first),
/// otherwise at the limit itself, moved back one if it would split a surrogate pair. Consecutive
/// windows overlap by at least the requested overlap, so any span up to that long - a jailbreak
/// sentence, a name, an address - lies whole inside at least one window.
/// </remarks>
internal static class TextChunker
{
    /// <summary>
    /// Splits <paramref name="text"/> into windows of at most <paramref name="maxLength"/> code units
    /// that overlap by at least <paramref name="overlap"/> code units.
    /// </summary>
    /// <returns>A single window covering the whole text when it already fits.</returns>
    public static IReadOnlyList<TextWindow> Split(string text, int maxLength, int overlap)
    {
        ArgumentNullException.ThrowIfNull(text);
        ValidateWindowSize(maxLength, overlap);

        if (text.Length <= maxLength)
            return [new TextWindow(0, text.Length)];

        var slack = Slack(overlap);

        var windows = new List<TextWindow>();
        var start = 0;
        while (text.Length - start > maxLength)
        {
            var end = FindBoundary(text, start + maxLength, slack);
            windows.Add(new TextWindow(start, end - start));

            // step back by the overlap, and a little further if that reaches a word boundary
            start = FindBoundary(text, end - overlap, slack);
        }

        windows.Add(new TextWindow(start, text.Length - start));
        return windows;
    }

    /// <summary>
    /// Throws unless windows of at most <paramref name="maxLength"/> code units can overlap by
    /// <paramref name="overlap"/> and still make progress through the text.
    /// </summary>
    public static void ValidateWindowSize(int maxLength, int overlap)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(overlap);

        // both boundaries of a window may give back their slack; the next window must still advance
        // and still reach far enough past the previous cut to hold anything that straddles it
        ArgumentOutOfRangeException.ThrowIfLessThan(maxLength, 2 * (overlap + Slack(overlap)));
    }

    /// <summary>
    /// The windows of <see cref="Split"/> as strings, leaving out those that are only whitespace -
    /// there is nothing in them to analyze. Null or whitespace text yields no windows at all.
    /// </summary>
    public static IEnumerable<string> SplitToStrings(string? text, int maxLength, int overlap)
    {
        if (string.IsNullOrWhiteSpace(text))
            yield break;

        foreach (var window in Split(text, maxLength, overlap))
        {
            if (!text.AsSpan(window.Start, window.Length).IsWhiteSpace())
                yield return text.Substring(window.Start, window.Length);
        }
    }

    /// <summary>
    /// Whether <paramref name="text"/> has at least <paramref name="count"/> text elements
    /// (user-perceived characters). That is the lowest of the ways a service may count characters,
    /// so text that passes this check meets a minimum length however the service measures it.
    /// </summary>
    public static bool HasAtLeastTextElements(string text, int count)
    {
        // a text element is at least one code unit, so a shorter string cannot qualify
        if (text.Length < count)
            return false;

        var seen = 0;
        for (var index = 0; index < text.Length && seen < count; seen++)
            index += StringInfo.GetNextTextElementLength(text, index);

        return seen >= count;
    }

    // how far back from the limit a boundary may move to land on whitespace
    private static int Slack(int overlap) => Math.Max(overlap / 2, 1);

    // the latest cut in (limit - slack, limit] that falls right after whitespace, preferring a line
    // break; without one, limit itself, moved back one if it would split a surrogate pair
    private static int FindBoundary(string text, int limit, int slack)
    {
        var afterWhitespace = -1;
        for (var cut = limit; cut > limit - slack; cut--)
        {
            var previous = text[cut - 1];
            if (previous == '\n')
                return cut;

            if (afterWhitespace < 0 && char.IsWhiteSpace(previous))
                afterWhitespace = cut;
        }

        if (afterWhitespace >= 0)
            return afterWhitespace;

        return char.IsLowSurrogate(text[limit]) && char.IsHighSurrogate(text[limit - 1]) ? limit - 1 : limit;
    }
}
