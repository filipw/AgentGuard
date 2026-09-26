using System.Buffers;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace AgentGuard.Core.Rules.ToolResult;

/// <summary>A run of encoded text in a tool result that decodes to text.</summary>
/// <param name="Start">Where the run starts in the scanned text.</param>
/// <param name="Length">The length of the run, line breaks of a wrapped block included.</param>
/// <param name="Encoding"><c>base64</c>, <c>hex</c> or <c>percent</c>.</param>
/// <param name="Decoded">The decoded text.</param>
internal sealed record EncodedRun(int Start, int Length, string Encoding, string Decoded);

/// <summary>
/// Finds base64, base64url, hex and percent-encoded runs in a tool result and decodes the ones
/// that carry text, for <see cref="ToolResultGuardrailOptions.DetectEncodedPayloads"/>.
/// </summary>
/// <remarks>
/// <para>
/// A base64 or base64url run is at least 24 characters (18 bytes). One wrapped over several lines
/// at a fixed width that is a multiple of four - MIME's 76, PEM's 64, the GitHub contents API's 60,
/// with real or JSON-escaped line breaks - is joined back into one run, and its lines are decoded
/// one by one when the whole does not decode to text. A run of hex digits is decoded as hex rather
/// than base64, as is a run of eight or more <c>\x</c> escapes. A percent-encoded run is a
/// whitespace-delimited run with at least two <c>%XX</c> escapes, such as a URL; <c>+</c> decodes
/// to a space. JWTs are not decoded: their claims are data, not instructions.
/// </para>
/// <para>
/// A run counts when its decoded form is text: at least eight characters, nine in ten of them
/// printable, a quarter of them letters. Binary payloads, identifiers and hashes decode to
/// neither, so they are dropped here. The work is bounded: at most <see cref="MaxRuns"/> runs and
/// <see cref="MaxEncodedLength"/> encoded characters are decoded per result, and a longer run is
/// decoded up to what is left of that budget.
/// </para>
/// </remarks>
internal static class EncodedPayloads
{
    /// <summary>The most encoded runs decoded in one tool result.</summary>
    internal const int MaxRuns = 1_024;

    /// <summary>The most encoded characters decoded in one tool result.</summary>
    internal const int MaxEncodedLength = 262_144;

    private const int MinBase64Length = 24;
    private const int MinWrappedLineLength = 40;
    private const int MaxWrappedLineLength = 128;
    private const RegexOptions Options = RegexOptions.Compiled | RegexOptions.CultureInvariant;
    private static readonly TimeSpan Timeout = TimeSpan.FromMilliseconds(200);

    // a run can only start where no alphabet character precedes it, so each run is scanned once
    private static readonly Regex Base64Run =
        new(@"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{" + MinBase64Length + ",}={0,2}", Options, Timeout);

    private static readonly Regex HexEscapeRun = new(@"(?:\\x[0-9A-Fa-f]{2}){8,}", Options, Timeout);

    // starts only after whitespace or at the start of the text; every group begins with '%',
    // which the characters between escapes exclude, so the scan is linear
    private static readonly Regex PercentRun =
        new(@"(?<!\S)[^\s%]*(?:%[0-9A-Fa-f]{2}[^\s%]*){2,}", Options, Timeout);

    private static readonly SearchValues<char> HexDigits = SearchValues.Create("0123456789abcdefABCDEF");

    private static readonly Regex JwtChain =
        new(@"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]*)?", Options, Timeout);

    /// <summary>The patterns the decoder runs, for warming and inspection.</summary>
    internal static IEnumerable<Regex> Patterns => [Base64Run, HexEscapeRun, PercentRun, JwtChain];

    /// <summary>Finds the encoded runs in <paramref name="text"/> that decode to text.</summary>
    /// <remarks>
    /// A pattern that exceeds its match timeout ends the search; the runs found up to then are
    /// still returned.
    /// </remarks>
    public static List<EncodedRun> Find(string text)
    {
        var runs = new List<EncodedRun>();
        var examined = 0;
        var budget = MaxEncodedLength;

        // decodes one run: null once the budget is spent, else whether it decoded to text
        bool? TryAdd(int start, int length, Func<string, (string Encoding, string? Decoded)> decode)
        {
            if (examined >= MaxRuns || budget <= 0)
                return null;

            examined++;
            var encoded = text.Substring(start, Math.Min(length, budget));
            budget -= encoded.Length;

            var (encoding, decoded) = decode(encoded);
            if (decoded is null || !IsText(decoded))
                return false;

            runs.Add(new EncodedRun(start, length, encoding, decoded));
            return true;
        }

        try
        {
            var jwts = new List<(int Start, int End)>();
            foreach (Match match in JwtChain.Matches(text))
                jwts.Add((match.Index, match.Index + match.Length));

            var covered = 0;
            var jwtIndex = 0;
            foreach (Match match in Base64Run.Matches(text))
            {
                // a line of a wrapped block already joined into the run before it
                if (match.Index < covered)
                    continue;

                var lines = WrappedBlockLines(text, match.Index, match.Index + match.Length);
                var (start, end) = (lines[0].Start, lines[^1].End);
                covered = end;

                while (jwtIndex < jwts.Count && jwts[jwtIndex].End <= start)
                    jwtIndex++;
                if (jwtIndex < jwts.Count && jwts[jwtIndex].Start < end)
                    continue;

                // a wrapped block is decoded whole, so an instruction split across its lines is
                // seen; when the whole is not text - binary lines with text lines after them -
                // each line gets its own chance
                var added = TryAdd(start, end - start, DecodeBase64OrHex);
                if (added is null)
                    return runs;

                if (added == false && lines.Count > 1)
                {
                    foreach (var (lineStart, lineEnd) in lines)
                    {
                        if (lineEnd - lineStart >= MinBase64Length && TryAdd(lineStart, lineEnd - lineStart, DecodeBase64OrHex) is null)
                            return runs;
                    }
                }
            }

            foreach (Match match in HexEscapeRun.Matches(text))
            {
                if (TryAdd(match.Index, match.Length, encoded => ("hex", DecodeHexEscapes(encoded))) is null)
                    return runs;
            }

            foreach (Match match in PercentRun.Matches(text))
            {
                if (TryAdd(match.Index, match.Length, encoded => ("percent", WebUtility.UrlDecode(encoded))) is null)
                    return runs;
            }
        }
        catch (RegexMatchTimeoutException)
        {
            // the search could not finish inside its budget; keep the runs found so far
        }

        return runs;
    }

    /// <summary>
    /// The lines of the base64 block that starts with the run <c>[start, end)</c>: just that run,
    /// unless it is the first line of a block wrapped at a fixed width - a multiple of four from
    /// 40 to 128 characters - in which case each following line break and line of nothing but
    /// base64 belongs to the block while the line before it had the full width. Linear in the block.
    /// </summary>
    private static List<(int Start, int End)> WrappedBlockLines(string text, int start, int end)
    {
        var lines = new List<(int Start, int End)> { (start, end) };
        var width = end - start;
        if (width % 4 != 0 || width is < MinWrappedLineLength or > MaxWrappedLineLength || text[end - 1] == '=')
            return lines;

        var lineLength = width;
        while (lineLength == width)
        {
            var next = SkipLineBreak(text, end);
            if (next < 0)
                break;

            var lineEnd = next;
            while (lineEnd < text.Length && IsBase64Char(text[lineEnd]))
                lineEnd++;

            var padded = lineEnd;
            while (padded < text.Length && padded - lineEnd < 2 && text[padded] == '=')
                padded++;

            if (lineEnd == next || !EndsLine(text, padded))
                break;

            lines.Add((next, padded));
            lineLength = padded - next;
            end = padded;
            if (padded > lineEnd)
                break;
        }

        return lines;
    }

    // the index after a line break at position i - a real one, or a JSON-escaped \n or \r\n - or
    // -1 when there is none
    private static int SkipLineBreak(string text, int i)
    {
        var rest = text.AsSpan(i);
        if (rest.StartsWith("\r\n", StringComparison.Ordinal)) return i + 2;
        if (rest.StartsWith("\n", StringComparison.Ordinal)) return i + 1;
        if (rest.StartsWith(@"\r\n", StringComparison.Ordinal)) return i + 4;
        if (rest.StartsWith(@"\n", StringComparison.Ordinal)) return i + 2;
        return -1;
    }

    // whether position i ends a line of a wrapped block: the end of the text, a line break, or
    // the quote closing the string the block sits in
    private static bool EndsLine(string text, int i) =>
        i >= text.Length || text[i] is '\r' or '\n' or '"' or '\'' || SkipLineBreak(text, i) >= 0;

    private static bool IsBase64Char(char c) => char.IsAsciiLetterOrDigit(c) || c is '+' or '/' or '-' or '_';

    private static (string Encoding, string? Decoded) DecodeBase64OrHex(string encoded)
    {
        // a run of hex digits (optionally 0x-prefixed) is hex, not base64; a trailing odd digit,
        // left by the budget, carries no whole byte
        var digits = encoded.AsSpan(encoded.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? 2 : 0);
        if (!digits.IsEmpty && !digits.ContainsAnyExcept(HexDigits))
            return ("hex", Utf8(Convert.FromHexString(digits[..(digits.Length & ~1)])));

        return ("base64", DecodeBase64(encoded));
    }

    private static string? DecodeBase64(string encoded)
    {
        var chars = new StringBuilder(encoded.Length + 2);
        for (var i = 0; i < encoded.Length; i++)
        {
            var c = encoded[i];
            if (c == '\\')
                i++;
            else if (c is '-' or '_')
                chars.Append(c == '-' ? '+' : '/');
            else if (IsBase64Char(c))
                chars.Append(c);
        }

        // unpadded base64url, or a run cut short by the budget: a lone trailing character carries
        // no whole byte, and the rest is padded back to a multiple of four
        if (chars.Length % 4 == 1)
            chars.Length--;
        while (chars.Length % 4 != 0)
            chars.Append('=');

        var bytes = new byte[chars.Length / 4 * 3];
        return Convert.TryFromBase64String(chars.ToString(), bytes, out var written)
            ? Utf8(bytes.AsSpan(0, written))
            : null;
    }

    // "\x69\x67..." to bytes; only whole four-character escapes, in case the budget cut the run
    private static string DecodeHexEscapes(string encoded)
    {
        var digits = new char[encoded.Length / 4 * 2];
        for (var i = 0; i < digits.Length / 2; i++)
        {
            digits[2 * i] = encoded[4 * i + 2];
            digits[2 * i + 1] = encoded[4 * i + 3];
        }

        return Utf8(Convert.FromHexString(digits));
    }

    private static string Utf8(ReadOnlySpan<byte> bytes) => Encoding.UTF8.GetString(bytes);

    // text rather than binary: at least eight characters, nine in ten printable (an invalid UTF-8
    // sequence decodes to U+FFFD, which is not), and a quarter letters
    private static bool IsText(string decoded)
    {
        if (decoded.Length < 8)
            return false;

        var printable = 0;
        var letters = 0;
        foreach (var c in decoded)
        {
            if (c == '\uFFFD' || (char.IsControl(c) && c is not ('\t' or '\n' or '\r')))
                continue;

            printable++;
            if (char.IsLetter(c))
                letters++;
        }

        return printable * 10 >= decoded.Length * 9 && letters * 4 >= decoded.Length;
    }
}
