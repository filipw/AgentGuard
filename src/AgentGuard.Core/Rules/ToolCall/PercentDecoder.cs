using System.Globalization;
using System.Text;

namespace AgentGuard.Core.Rules.ToolCall;

/// <summary>
/// Lenient percent-decoding for inspection: decodes what a permissive server or file API would, so a
/// payload hidden behind an encoding is checked in the form it takes once it reaches its target.
/// </summary>
/// <remarks>
/// Beyond standard <c>%XX</c> escapes this decodes IIS-style <c>%uXXXX</c> escapes and overlong UTF-8
/// forms such as <c>%c0%ae</c> (a dot) - strict decoders reject those, but some servers accept them,
/// which is what made them a traversal trick. Bytes that form no character become U+FFFD. The output
/// is for pattern matching only and is never handed back to a caller.
/// </remarks>
internal static class PercentDecoder
{
    /// <summary>
    /// Decodes <paramref name="text"/> once. Returns the same instance when there is nothing to decode.
    /// </summary>
    /// <param name="text">The text to decode.</param>
    /// <param name="plusAsSpace">Whether <c>+</c> decodes to a space, as in form-encoded query strings.</param>
    internal static string Decode(string text, bool plusAsSpace = false)
    {
        if (text.IndexOf('%') < 0 && !(plusAsSpace && text.Contains('+')))
            return text;

        var builder = new StringBuilder(text.Length);
        var bytes = new List<byte>();
        var changed = false;

        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];

            if (c == '%' && TryHexByte(text, i + 1, out var value))
            {
                bytes.Add(value);
                i += 2;
                changed = true;
                continue;
            }

            FlushUtf8(bytes, builder);

            if (c == '%' && i + 5 < text.Length && (text[i + 1] == 'u' || text[i + 1] == 'U')
                && int.TryParse(text.AsSpan(i + 2, 4), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out var unit))
            {
                builder.Append((char)unit);
                i += 5;
                changed = true;
            }
            else if (c == '+' && plusAsSpace)
            {
                builder.Append(' ');
                changed = true;
            }
            else
            {
                builder.Append(c);
            }
        }

        FlushUtf8(bytes, builder);
        return changed ? builder.ToString() : text;
    }

    /// <summary>
    /// Decodes <paramref name="text"/> repeatedly, up to <paramref name="maxRounds"/> times, and returns
    /// each distinct result in order - one per encoding layer peeled off. Empty when nothing decodes.
    /// </summary>
    internal static List<string> DecodeLayers(string text, int maxRounds, bool plusAsSpace = false)
    {
        var layers = new List<string>();
        var current = text;

        for (var round = 0; round < maxRounds; round++)
        {
            var decoded = Decode(current, plusAsSpace);
            if (ReferenceEquals(decoded, current))
                break;

            layers.Add(decoded);
            current = decoded;
        }

        return layers;
    }

    private static bool TryHexByte(string text, int index, out byte value)
    {
        value = 0;
        if (index + 1 >= text.Length)
            return false;

        var high = HexValue(text[index]);
        var low = HexValue(text[index + 1]);
        if (high < 0 || low < 0)
            return false;

        value = (byte)((high << 4) | low);
        return true;
    }

    private static int HexValue(char c) => c switch
    {
        >= '0' and <= '9' => c - '0',
        >= 'a' and <= 'f' => c - 'a' + 10,
        >= 'A' and <= 'F' => c - 'A' + 10,
        _ => -1
    };

    /// <summary>
    /// Appends the pending bytes as UTF-8, accepting overlong forms and replacing anything that forms
    /// no character with U+FFFD.
    /// </summary>
    private static void FlushUtf8(List<byte> bytes, StringBuilder builder)
    {
        var i = 0;
        while (i < bytes.Count)
        {
            var lead = bytes[i];
            int length;
            int codePoint;

            if (lead < 0x80)
            {
                builder.Append((char)lead);
                i++;
                continue;
            }

            if (lead is >= 0xC0 and <= 0xDF)
            {
                length = 2;
                codePoint = lead & 0x1F;
            }
            else if (lead is >= 0xE0 and <= 0xEF)
            {
                length = 3;
                codePoint = lead & 0x0F;
            }
            else if (lead is >= 0xF0 and <= 0xF7)
            {
                length = 4;
                codePoint = lead & 0x07;
            }
            else
            {
                builder.Append('�');
                i++;
                continue;
            }

            if (i + length > bytes.Count)
            {
                builder.Append('�');
                i++;
                continue;
            }

            var valid = true;
            for (var k = 1; k < length; k++)
            {
                var next = bytes[i + k];
                if ((next & 0xC0) != 0x80)
                {
                    valid = false;
                    break;
                }

                codePoint = (codePoint << 6) | (next & 0x3F);
            }

            if (!valid || codePoint > 0x10FFFF || codePoint is >= 0xD800 and <= 0xDFFF)
            {
                builder.Append('�');
                i++;
                continue;
            }

            builder.Append(char.ConvertFromUtf32(codePoint));
            i += length;
        }

        bytes.Clear();
    }
}
