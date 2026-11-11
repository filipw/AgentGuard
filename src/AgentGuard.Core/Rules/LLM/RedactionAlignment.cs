using System.Text;
using System.Text.RegularExpressions;

namespace AgentGuard.Core.Rules.LLM;

/// <summary>
/// Checks a judge's redacted rewrite of a message against the message itself, and applies it to the
/// message rather than taking the rewrite on trust.
/// </summary>
/// <remarks>
/// <para>
/// A rewrite is a redaction when it is the original with stretches replaced by placeholders: the
/// text between its placeholders must appear in the original, in the same order, starting at the
/// original's start and ending at its end. A rewrite that says something else, stops early, or
/// replaces more than a placeholder plausibly stands for is not one.
/// </para>
/// <para>
/// The result is built from the original - each replaced stretch swapped for the judge's
/// placeholder - so everything that is kept is the text as it was written, whatever the judge did
/// to its spacing or capitalization.
/// </para>
/// </remarks>
internal static partial class RedactionAlignment
{
    // the longest stretch one placeholder may stand for: a postal address or a long name fits, a
    // dropped paragraph does not
    private const int MaxSpanPerPlaceholder = 256;

    /// <summary>Whether <paramref name="text"/> holds something that reads as a redaction placeholder.</summary>
    internal static bool ContainsPlaceholder(string text) => Placeholder().IsMatch(text);

    /// <summary>Whether two texts are the same apart from spacing and capitalization.</summary>
    internal static bool AreEquivalent(string a, string b) =>
        string.Equals(Normalize(a).Text, Normalize(b).Text, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Returns <paramref name="original"/> with the stretches <paramref name="redacted"/> replaces
    /// swapped for its placeholders, or <c>null</c> when <paramref name="redacted"/> is not a
    /// redaction of it.
    /// </summary>
    internal static string? Apply(string original, string redacted)
    {
        var (source, map) = Normalize(original);
        var rewrite = Normalize(redacted).Text;

        // placeholders separated only by a space stand for one stretch ("[FIRST NAME] [LAST NAME]")
        var placeholders = PlaceholderRun().Matches(rewrite);
        if (placeholders.Count == 0)
            return null;

        var result = new StringBuilder(original.Length);
        var copiedTo = 0;   // in the original
        var position = 0;   // in the normalized original
        var kept = 0;       // in the rewrite

        for (var i = 0; i <= placeholders.Count; i++)
        {
            var isLast = i == placeholders.Count;
            var segmentEnd = isLast ? rewrite.Length : placeholders[i].Index;

            // spacing next to a placeholder is the judge's; only the words have to line up
            var segment = rewrite.AsSpan(kept, segmentEnd - kept);
            if (i > 0)
                segment = segment.TrimStart();
            if (!isLast)
                segment = segment.TrimEnd();

            int found;
            if (i == 0)
            {
                found = source.AsSpan().StartsWith(segment, StringComparison.OrdinalIgnoreCase) ? 0 : -1;
            }
            else if (isLast)
            {
                found = source.Length - segment.Length;
                if (found < position || !source.AsSpan(found).Equals(segment, StringComparison.OrdinalIgnoreCase))
                    found = -1;
            }
            else
            {
                var offset = source.AsSpan(position).IndexOf(segment, StringComparison.OrdinalIgnoreCase);
                found = offset < 0 ? -1 : position + offset;
            }

            if (found < 0)
                return null;

            if (i > 0)
            {
                // the stretch the previous placeholder replaces, without the spacing around it
                var start = position;
                var end = found;
                while (start < end && source[start] == ' ')
                    start++;
                while (end > start && source[end - 1] == ' ')
                    end--;

                var placeholder = placeholders[i - 1];
                var count = Placeholder().Count(placeholder.ValueSpan);
                if (end - start > MaxSpanPerPlaceholder * count)
                    return null;

                var originalStart = start < source.Length ? map[start] : original.Length;
                var originalEnd = end > start ? map[end - 1] + 1 : originalStart;

                result.Append(original, copiedTo, originalStart - copiedTo).Append(placeholder.Value);
                copiedTo = originalEnd;
            }

            position = found + segment.Length;
            kept = isLast ? rewrite.Length : placeholders[i].Index + placeholders[i].Length;
        }

        return result.Append(original, copiedTo, original.Length - copiedTo).ToString();
    }

    // Trims the text and collapses each run of white space to one space, keeping for every character
    // of the result the index it came from.
    private static (string Text, int[] Map) Normalize(string text)
    {
        var builder = new StringBuilder(text.Length);
        var map = new int[text.Length];
        var pendingSpace = -1;

        for (var i = 0; i < text.Length; i++)
        {
            if (char.IsWhiteSpace(text[i]))
            {
                if (builder.Length > 0 && pendingSpace < 0)
                    pendingSpace = i;
                continue;
            }

            if (pendingSpace >= 0)
            {
                map[builder.Length] = pendingSpace;
                builder.Append(' ');
                pendingSpace = -1;
            }

            map[builder.Length] = i;
            builder.Append(text[i]);
        }

        return (builder.ToString(), map);
    }

    // [REDACTED], [NAME], [REDACTED: email], <EMAIL_ADDRESS>, *** and block characters
    private const string PlaceholderPattern = @"\[[^\[\]\r\n]{1,48}\]|<[A-Z][A-Z0-9_ ]{1,40}>|\*{3,}|█{2,}";

    [GeneratedRegex(PlaceholderPattern, RegexOptions.CultureInvariant)]
    private static partial Regex Placeholder();

    [GeneratedRegex("(?:" + PlaceholderPattern + ")(?: ?(?:" + PlaceholderPattern + "))*", RegexOptions.CultureInvariant)]
    private static partial Regex PlaceholderRun();
}
