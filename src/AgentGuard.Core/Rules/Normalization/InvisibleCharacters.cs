using System.Buffers;
using System.Text;

namespace AgentGuard.Core.Rules.Normalization;

/// <summary>
/// Code-point level handling of characters that render as nothing but still reach the model.
/// </summary>
/// <remarks>
/// Unicode tag characters (U+E0000-U+E007F) mirror printable ASCII one-to-one outside the Basic
/// Multilingual Plane, so each one is a surrogate pair in a .NET string. Everything here walks the text by
/// <see cref="Rune"/>, so a pair is never split, and malformed UTF-16 (a lone surrogate) is copied through untouched rather than
/// being rewritten as U+FFFD.
/// </remarks>
internal static class InvisibleCharacters
{
    private const int TagBlockFirst = 0xE0000;
    private const int TagBlockLast = 0xE007F;

    // the tag characters that mirror printable ASCII, U+E0020 (space) to U+E007E (tilde)
    private const int PrintableTagFirst = 0xE0020;
    private const int PrintableTagLast = 0xE007E;

    /// <summary>Whether <paramref name="rune"/> is in the Unicode Tags block (U+E0000-U+E007F).</summary>
    internal static bool IsUnicodeTag(Rune rune) => rune.Value is >= TagBlockFirst and <= TagBlockLast;

    /// <summary>
    /// Returns <paramref name="text"/> without the code points <paramref name="isInvisible"/>
    /// selects, or <c>null</c> when there was nothing to remove.
    /// </summary>
    internal static string? Remove(string text, Func<Rune, bool> isInvisible)
    {
        StringBuilder? builder = null;
        var span = text.AsSpan();
        var index = 0;

        while (index < span.Length)
        {
            var status = Rune.DecodeFromUtf16(span[index..], out var rune, out var consumed);

            if (status == OperationStatus.Done && isInvisible(rune))
            {
                // first removal: copy everything kept so far, then keep appending from here on
                builder ??= new StringBuilder(text.Length).Append(text, 0, index);
            }
            else
            {
                builder?.Append(text, index, consumed);
            }

            index += consumed;
        }

        return builder?.ToString();
    }

    /// <summary>
    /// Decodes the ASCII that tag characters spell, or returns <c>null</c> when the text carries
    /// none. Separate runs of tags are joined with a space; the non-printing language and cancel
    /// tags are dropped.
    /// </summary>
    internal static string? DecodeUnicodeTags(string text)
    {
        StringBuilder? decoded = null;
        var span = text.AsSpan();
        var index = 0;
        var inRun = false;

        while (index < span.Length)
        {
            var status = Rune.DecodeFromUtf16(span[index..], out var rune, out var consumed);
            index += consumed;

            if (status == OperationStatus.Done && rune.Value is >= PrintableTagFirst and <= PrintableTagLast)
            {
                decoded ??= new StringBuilder();
                if (!inRun && decoded.Length > 0)
                    decoded.Append(' ');

                decoded.Append((char)(rune.Value - TagBlockFirst));
                inRun = true;
            }
            else if (!(status == OperationStatus.Done && IsUnicodeTag(rune)))
            {
                inRun = false;
            }
        }

        return decoded?.ToString();
    }
}
