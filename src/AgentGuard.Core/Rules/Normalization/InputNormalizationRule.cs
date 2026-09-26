using System.Collections.Frozen;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using AgentGuard.Core.Abstractions;

namespace AgentGuard.Core.Rules.Normalization;

/// <summary>
/// Options for input normalization pre-processing.
/// </summary>
public sealed class InputNormalizationOptions
{
    /// <summary>Whether to detect and decode base64-encoded segments. Default: true.</summary>
    public bool DecodeBase64 { get; init; } = true;

    /// <summary>Whether to detect and decode hex-encoded segments (\x69\x67...). Default: true.</summary>
    public bool DecodeHex { get; init; } = true;

    /// <summary>Whether to detect and reverse reversed text blocks. Default: true.</summary>
    public bool DetectReversedText { get; init; } = true;

    /// <summary>
    /// Whether to undo the Unicode used to disguise Latin text: styled and enclosed letters become
    /// plain letters, and lookalike letters inside mixed-script words become Latin (e.g. the Cyrillic
    /// а in "аll" → Latin a). Default: true.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Only the characters used to disguise text are rewritten, so text in other scripts and ordinary
    /// compatibility characters (superscripts, subscripts, fractions, ligatures, CJK punctuation)
    /// reach the model as written. The rewritten set:
    /// </para>
    /// <list type="bullet">
    /// <item><description>Fullwidth Latin letters (U+FF21-U+FF3A, U+FF41-U+FF5A) become ASCII, together with the
    /// fullwidth digits and punctuation in the same unbroken run of fullwidth characters. A run
    /// without a letter, such as the fullwidth punctuation and digits of CJK text, stays.</description></item>
    /// <item><description>Mathematical alphanumeric symbols (U+1D400-U+1D7FF: bold, italic, script, fraktur,
    /// double-struck, sans-serif and monospace letters and digits) become the plain letters and
    /// digits.</description></item>
    /// <item><description>Circled Latin letters (U+24B6-U+24E9) and the squared, negative circled and negative
    /// squared Latin capitals (U+1F130-U+1F149, U+1F150-U+1F169, U+1F170-U+1F189) become plain
    /// letters, except when an emoji variation selector (U+FE0F) presents one as an emoji.</description></item>
    /// <item><description>Cyrillic and Greek letters that look like Latin ones (а, е, о, р, с, і, ѕ, ο, ι, α, ν
    /// and others) become Latin inside a word that also contains Latin letters. A word written
    /// entirely in Cyrillic or Greek is left alone. The whole word counts, so scientific shorthand
    /// that joins a Greek symbol to a Latin letter (Kα) is folded too.</description></item>
    /// </list>
    /// <para>
    /// Other compatibility characters are never rewritten. When their compatibility (NFKC) form
    /// reveals injection vocabulary that the text hides - an instruction spelled in superscript
    /// letters, for example - that form is appended as a decoded view, like the decoders' output. A
    /// lone surrogate becomes U+FFFD.
    /// </para>
    /// </remarks>
    public bool NormalizeUnicode { get; init; } = true;

    /// <summary>Whether to decode leetspeak substitutions (e.g. 1gn0r3 → ignore). Default: true.</summary>
    public bool DecodeLeetspeak { get; init; } = true;

    /// <summary>
    /// Whether to strip invisible Unicode characters (zero-width joiners, Unicode tag characters,
    /// etc.). Default: true.
    /// </summary>
    /// <remarks>
    /// Unicode tag characters (U+E0000-U+E007F) spell ASCII that a model can read but a person
    /// cannot see ("ASCII smuggling"). Besides being stripped, what they spell is appended as a
    /// decoded view, like the other decoders, so downstream rules can inspect it.
    /// </remarks>
    public bool StripInvisibleUnicode { get; init; } = true;

    /// <summary>
    /// Minimum length of a base64-encoded segment to attempt decoding.
    /// Shorter segments are likely to be false positives (e.g. common English words).
    /// Default: 16 characters.
    /// </summary>
    public int MinBase64Length { get; init; } = 16;
}

/// <summary>
/// Pre-processes input text by decoding common evasion encodings so that downstream
/// rules (both regex and LLM) see plaintext. Runs at order 5, before all other rules.
///
/// If encoded content is detected, the decoded version is appended to the original text
/// (separated by a newline) so downstream rules can match against both forms.
/// This avoids false positives from aggressive decoding while still catching evasions.
///
/// Informed by the Arcanum Prompt Injection Taxonomy evasion categories.
/// </summary>
public sealed partial class InputNormalizationRule : IGuardrailRule
{
    private readonly InputNormalizationOptions _options;

    /// <summary>Initializes a new instance of the <see cref="InputNormalizationRule"/> class.</summary>
    /// <param name="options">Which decodings to attempt. Defaults when null.</param>
    public InputNormalizationRule(InputNormalizationOptions? options = null)
        => _options = options ?? new();

    /// <inheritdoc />
    public string Name => "input-normalization";

    /// <inheritdoc />
    public GuardrailPhase Phase => GuardrailPhase.Input;

    /// <inheritdoc />
    public int Order => 5;

    /// <inheritdoc />
    public ValueTask<GuardrailResult> EvaluateAsync(
        GuardrailContext context, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(context.Text))
            return ValueTask.FromResult(GuardrailResult.Passed());

        var text = context.Text;

        // Normalization passes rewrite the working text in place. They run before the decoders, so
        // invisible characters interleaved into an encoded payload are gone before it is decoded.
        if (_options.NormalizeUnicode)
        {
            text = NormalizeUnicode(text);
        }

        // tag characters are an ASCII encoding in their own right, so what they spell is decoded
        // before they are stripped and surfaced below alongside the other decoded views.
        string? tagPayload = null;
        if (_options.StripInvisibleUnicode)
        {
            tagPayload = InvisibleCharacters.DecodeUnicodeTags(text);
            text = StripInvisibleCharacters(text) ?? text;
        }

        // Decoding passes produce extra views of the text rather than replacing it, so downstream
        // rules can match the plaintext without the decoders' false positives rewriting the input.
        // Only distinct views are kept.
        var decodedSegments = new List<string>();

        void AddView(string? view)
        {
            if (view is null || string.Equals(view, text, StringComparison.Ordinal))
                return;
            if (!decodedSegments.Contains(view, StringComparer.Ordinal))
                decodedSegments.Add(view);
        }

        AddView(tagPayload);

        if (_options.NormalizeUnicode)
            AddView(DecodeCompatibilityForms(text));

        if (_options.DecodeBase64)
            AddView(DecodeBase64Segments(text));

        if (_options.DecodeHex)
            AddView(DecodeHexSequences(text));

        if (_options.DetectReversedText)
            AddView(DetectAndReverseText(text));

        if (_options.DecodeLeetspeak)
            AddView(DecodeLeetspeak(text));

        var normalizationChanged = !string.Equals(text, context.Text, StringComparison.Ordinal);

        if (decodedSegments.Count == 0 && !normalizationChanged)
            return ValueTask.FromResult(GuardrailResult.Passed());

        // Append decoded content so downstream rules can evaluate both original and decoded forms
        var combined = decodedSegments.Count == 0
            ? text
            : text + "\n[DECODED]\n" + string.Join("\n", decodedSegments);

        return ValueTask.FromResult(
            GuardrailResult.Modified(combined, "Input contained encoded content that was decoded for analysis."));
    }

    /// <summary>
    /// Finds base64-encoded segments and attempts to decode them.
    /// Returns the decoded text if valid UTF-8 text was found, null otherwise.
    /// </summary>
    internal string? DecodeBase64Segments(string text)
    {
        var matches = Base64Pattern().Matches(text);
        if (matches.Count == 0)
            return null;

        var decodedParts = new List<string>();
        foreach (Match match in matches)
        {
            var candidate = match.Value.Trim();
            if (candidate.Length < _options.MinBase64Length)
                continue;

            try
            {
                var bytes = Convert.FromBase64String(candidate);
                var decoded = Encoding.UTF8.GetString(bytes);

                // Only include if the decoded text looks like readable text (mostly printable ASCII)
                if (IsPrintableText(decoded))
                    decodedParts.Add(decoded);
            }
            catch (FormatException)
            {
                // Not valid base64, skip
            }
        }

        return decodedParts.Count > 0 ? string.Join(" ", decodedParts) : null;
    }

    /// <summary>
    /// Decodes hex escape sequences like \x69\x67\x6e\x6f\x72\x65 → "ignore".
    /// </summary>
    internal static string? DecodeHexSequences(string text)
    {
        if (!text.Contains("\\x", StringComparison.OrdinalIgnoreCase))
            return null;

        var decoded = HexPattern().Replace(text, match =>
        {
            var hexValue = match.Groups[1].Value;
            if (byte.TryParse(hexValue, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var b))
                return ((char)b).ToString();
            return match.Value;
        });

        return decoded != text ? decoded : null;
    }

    /// <summary>
    /// Detects text that appears to be reversed and returns the reversed version.
    /// Uses heuristic: if the reversed text contains more common English words than the original,
    /// it's likely reversed.
    /// </summary>
    internal static string? DetectAndReverseText(string text)
    {
        // Only check segments that are at least 10 chars and don't look like normal text
        var words = SplitWords(text);
        if (words.Length < 2)
            return null;

        // reversed by code point: reversing UTF-16 units would turn every surrogate pair into two lone surrogates
        var runes = text.EnumerateRunes().ToArray();
        Array.Reverse(runes);
        var reversed = ToText(runes);

        var originalHits = CountKnownWords(text);
        var reversedHits = CountKnownWords(reversed);

        // If the reversed version has significantly more recognizable words, it was likely reversed
        return reversedHits > originalHits + 2 ? reversed : null;
    }

    /// <summary>
    /// Undoes the Unicode used to disguise Latin text: fullwidth, mathematical and enclosed letters
    /// become plain letters, and Cyrillic or Greek lookalikes become Latin inside words that mix them
    /// with Latin letters. Everything else, including text written entirely in another script, is
    /// returned as it was, except that a lone surrogate becomes U+FFFD.
    /// </summary>
    /// <remarks>
    /// <see cref="InputNormalizationOptions.NormalizeUnicode"/> documents the exact set of characters.
    /// </remarks>
    internal static string NormalizeUnicode(string text)
    {
        if (Ascii.IsValid(text))
            return text;

        // enumerating by rune turns a lone surrogate into U+FFFD, which every later step can handle
        var runes = text.EnumerateRunes().ToArray();

        FoldStyledLetters(runes);
        FoldMixedScriptLookalikes(runes);

        return ToText(runes);
    }

    /// <summary>
    /// Returns the compatibility (NFKC) form of <paramref name="text"/> when it reveals injection
    /// vocabulary that the text hides - words spelled in superscript letters, for example - and null
    /// otherwise, so superscripts, fractions and ligatures in ordinary text produce no view.
    /// </summary>
    internal static string? DecodeCompatibilityForms(string text)
    {
        if (Ascii.IsValid(text))
            return null;

        string folded;
        try
        {
            folded = text.Normalize(NormalizationForm.FormKC);
        }
        catch (ArgumentException)
        {
            // malformed UTF-16; NormalizeUnicode replaces lone surrogates before this runs
            return null;
        }

        if (string.Equals(folded, text, StringComparison.Ordinal))
            return null;

        return CountKnownWords(folded) > CountKnownWords(text) + 1 ? folded : null;
    }

    private static void FoldStyledLetters(Rune[] runes)
    {
        for (var i = 0; i < runes.Length; i++)
        {
            var value = runes[i].Value;

            if (IsFullwidthAscii(value))
            {
                // a run of fullwidth characters is folded only when it holds a letter, so a fullwidth
                // word becomes ASCII while the fullwidth punctuation and digits of CJK text stay
                var end = i;
                var hasLetter = false;
                while (end < runes.Length && (IsFullwidthAscii(runes[end].Value) || IsFormatCharacter(runes[end])))
                {
                    hasLetter |= IsFullwidthLetter(runes[end].Value);
                    end++;
                }

                if (hasLetter)
                {
                    for (var j = i; j < end; j++)
                    {
                        if (IsFullwidthAscii(runes[j].Value))
                            runes[j] = new Rune(runes[j].Value - FullwidthOffset);
                    }
                }

                i = end - 1;
                continue;
            }

            // an emoji variation selector marks an enclosed letter such as the parking sign as an emoji
            var isEmoji = i + 1 < runes.Length && runes[i + 1].Value == EmojiVariationSelector;
            if (!isEmoji && StyledLetters.TryGetValue(value, out var plain))
                runes[i] = plain;
        }
    }

    private static void FoldMixedScriptLookalikes(Rune[] runes)
    {
        var start = 0;
        while (start < runes.Length)
        {
            if (!IsWordPart(runes[start]))
            {
                start++;
                continue;
            }

            var end = start;
            var hasLatin = false;
            var hasLookalike = false;
            while (end < runes.Length && IsWordPart(runes[end]))
            {
                hasLatin |= IsLatinLetter(runes[end].Value);
                hasLookalike |= HomoglyphMap.ContainsKey(runes[end].Value);
                end++;
            }

            // a word that mixes Latin letters with lookalikes is the spoofing pattern; a word written
            // entirely in Cyrillic or Greek is genuine text and stays as it is
            if (hasLatin && hasLookalike)
            {
                for (var i = start; i < end; i++)
                {
                    if (HomoglyphMap.TryGetValue(runes[i].Value, out var latin))
                        runes[i] = new Rune(latin);
                }
            }

            start = end;
        }
    }

    // letters, digits, combining marks and invisible format characters: a zero-width character
    // inside a word must not split it into single-script halves
    private static bool IsWordPart(Rune rune) => Rune.GetUnicodeCategory(rune) is
        UnicodeCategory.UppercaseLetter or UnicodeCategory.LowercaseLetter or UnicodeCategory.TitlecaseLetter
        or UnicodeCategory.ModifierLetter or UnicodeCategory.OtherLetter or UnicodeCategory.DecimalDigitNumber
        or UnicodeCategory.NonSpacingMark or UnicodeCategory.SpacingCombiningMark or UnicodeCategory.EnclosingMark
        or UnicodeCategory.Format;

    private static bool IsFormatCharacter(Rune rune) => Rune.GetUnicodeCategory(rune) == UnicodeCategory.Format;

    private static bool IsLatinLetter(int value) => value is
        (>= 'A' and <= 'Z') or (>= 'a' and <= 'z')
        or (>= 0x00C0 and <= 0x024F and not 0x00D7 and not 0x00F7)
        or (>= 0x1E00 and <= 0x1EFF);

    private const int FullwidthOffset = 0xFEE0;
    private const int EmojiVariationSelector = 0xFE0F;

    // U+FF01-U+FF5E mirror printable ASCII U+0021-U+007E
    private static bool IsFullwidthAscii(int value) => value is >= 0xFF01 and <= 0xFF5E;

    private static bool IsFullwidthLetter(int value) => value is (>= 0xFF21 and <= 0xFF3A) or (>= 0xFF41 and <= 0xFF5A);

    private static readonly FrozenDictionary<int, Rune> StyledLetters = BuildStyledLetters();

    private static FrozenDictionary<int, Rune> BuildStyledLetters()
    {
        var map = new Dictionary<int, Rune>();

        // mathematical alphanumerics, circled letters and squared capitals decompose to plain letters
        AddCompatibilityForms(map, 0x1D400, 0x1D7FF);
        AddCompatibilityForms(map, 0x24B6, 0x24E9);
        AddCompatibilityForms(map, 0x1F130, 0x1F149);

        // the negative circled and negative squared capitals have no decomposition; both run A to Z
        for (var i = 0; i < 26; i++)
        {
            map[0x1F150 + i] = new Rune('A' + i);
            map[0x1F170 + i] = new Rune('A' + i);
        }

        return map.ToFrozenDictionary();
    }

    private static void AddCompatibilityForms(Dictionary<int, Rune> map, int first, int last)
    {
        for (var value = first; value <= last; value++)
        {
            var original = char.ConvertFromUtf32(value);
            string folded;
            try
            {
                folded = original.Normalize(NormalizationForm.FormKC);
            }
            catch (ArgumentException)
            {
                continue;
            }

            // only one-to-one foldings; an unassigned code point normalizes to itself
            if (!string.Equals(folded, original, StringComparison.Ordinal)
                && Rune.TryGetRuneAt(folded, 0, out var rune)
                && rune.Utf16SequenceLength == folded.Length)
            {
                map[value] = rune;
            }
        }
    }

    private static string ToText(Rune[] runes)
    {
        var sb = new StringBuilder(runes.Length);
        Span<char> buffer = stackalloc char[2];
        foreach (var rune in runes)
        {
            sb.Append(buffer[..rune.EncodeToUtf16(buffer)]);
        }

        return sb.ToString();
    }

    /// <summary>
    /// Strips invisible Unicode characters used to evade detection:
    /// zero-width spaces, zero-width joiners, zero-width non-joiners,
    /// Unicode tag characters (U+E0000-U+E007F), soft hyphens, and other invisible formatting characters.
    /// Returns null if no invisible characters were found.
    /// </summary>
    /// <remarks>
    /// Walks the text by code point: tag characters are surrogate pairs, which a per-char loop
    /// never recognises.
    /// </remarks>
    internal static string? StripInvisibleCharacters(string text) =>
        InvisibleCharacters.Remove(text, IsInvisibleCharacter);

    private static bool IsInvisibleCharacter(Rune rune) =>
        InvisibleCharacters.IsUnicodeTag(rune) || (rune.IsBmp && IsInvisibleCharacter((char)rune.Value));

    private static bool IsInvisibleCharacter(char c) => c switch
    {
        '\u200B' => true, // Zero-width space
        '\u200C' => true, // Zero-width non-joiner
        '\u200D' => true, // Zero-width joiner
        '\u200E' => true, // Left-to-right mark
        '\u200F' => true, // Right-to-left mark
        '\u2060' => true, // Word joiner
        '\u2061' => true, // Function application
        '\u2062' => true, // Invisible times
        '\u2063' => true, // Invisible separator
        '\u2064' => true, // Invisible plus
        '\uFEFF' => true, // BOM / zero-width no-break space
        '\u00AD' => true, // Soft hyphen
        '\u034F' => true, // Combining grapheme joiner
        '\u061C' => true, // Arabic letter mark
        '\u180E' => true, // Mongolian vowel separator
        _ => false
    };

    /// <summary>
    /// Decodes common leetspeak substitutions to reveal hidden injection attempts.
    /// Only triggers if the decoded version contains known injection-related words
    /// that the original did not, reducing false positives.
    /// </summary>
    internal static string? DecodeLeetspeak(string text)
    {
        var decoded = new StringBuilder(text.Length);
        foreach (var c in text)
        {
            decoded.Append(LeetMap.TryGetValue(c, out var replacement) ? replacement : c);
        }

        var decodedStr = decoded.ToString();
        if (decodedStr == text)
            return null;

        // Only report as decoded if the substitution reveals significantly more
        // injection-related words (threshold of +2 to reduce false positives from
        // normal text containing numbers like "3 cats and 4 dogs")
        var originalHits = CountKnownWords(text.ToLowerInvariant());
        var decodedHits = CountKnownWords(decodedStr.ToLowerInvariant());

        return decodedHits > originalHits + 1 ? decodedStr : null;
    }

    // Common leetspeak substitutions
    private static readonly Dictionary<char, char> LeetMap = new()
    {
        ['0'] = 'o',
        ['1'] = 'i',
        ['3'] = 'e',
        ['4'] = 'a',
        ['5'] = 's',
        ['7'] = 't',
        ['@'] = 'a',
        ['!'] = 'i',
    };

    private static bool IsPrintableText(string text)
    {
        if (string.IsNullOrEmpty(text))
            return false;

        var printable = 0;
        foreach (var c in text)
        {
            if (c is >= ' ' and <= '~' or '\n' or '\r' or '\t')
                printable++;
        }

        return (double)printable / text.Length > 0.8;
    }

    private static int CountKnownWords(string text)
    {
        var words = SplitWords(text);
        var count = 0;
        foreach (var word in words)
        {
            if (CommonWords.Contains(word.Trim('.', ',', '!', '?', ';', ':').ToLowerInvariant()))
                count++;
        }
        return count;
    }

    // any whitespace separates words: line breaks, no-break and other Unicode spaces, not just ' '
    private static string[] SplitWords(string text) =>
        text.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);

    // Words commonly found in prompt injection attacks when reversed
    private static readonly HashSet<string> CommonWords =
    [
        "ignore", "previous", "instructions", "system", "prompt", "override",
        "forget", "disregard", "pretend", "rules", "new", "now", "you", "are",
        "the", "all", "your", "show", "tell", "me", "what", "how", "is", "do",
        "act", "as", "if", "a", "an", "and", "or", "not", "no", "be", "to",
        "this", "that", "it", "in", "for", "with", "on", "from", "but",
    ];

    // Cyrillic and Greek letters that look like Latin ones, folded only inside mixed-script words
    private static readonly FrozenDictionary<int, char> HomoglyphMap = new Dictionary<int, char>
    {
        // Cyrillic
        ['а'] = 'a', ['А'] = 'A',
        ['с'] = 'c', ['С'] = 'C',
        ['е'] = 'e', ['Е'] = 'E',
        ['о'] = 'o', ['О'] = 'O',
        ['р'] = 'p', ['Р'] = 'P',
        ['х'] = 'x', ['Х'] = 'X',
        ['у'] = 'y', ['У'] = 'Y',
        ['і'] = 'i', ['І'] = 'I',
        ['ј'] = 'j', ['Ј'] = 'J',
        ['ѕ'] = 's', ['Ѕ'] = 'S',
        ['һ'] = 'h',
        ['ԁ'] = 'd',
        ['ԛ'] = 'q',
        ['ԝ'] = 'w',
        ['В'] = 'B',
        ['Н'] = 'H',
        ['К'] = 'K',
        ['М'] = 'M',
        ['Т'] = 'T',
        // Greek
        ['α'] = 'a', ['Α'] = 'A',
        ['ε'] = 'e', ['Ε'] = 'E',
        ['ι'] = 'i', ['Ι'] = 'I',
        ['ο'] = 'o', ['Ο'] = 'O',
        ['κ'] = 'k', ['Κ'] = 'K',
        ['ρ'] = 'p', ['Ρ'] = 'P',
        ['τ'] = 't', ['Τ'] = 'T',
        ['υ'] = 'u', ['Υ'] = 'Y',
        ['χ'] = 'x', ['Χ'] = 'X',
        ['ν'] = 'v', ['Ν'] = 'N',
        ['Β'] = 'B',
        ['Η'] = 'H',
        ['Μ'] = 'M',
        ['Ζ'] = 'Z',
    }.ToFrozenDictionary();

    [GeneratedRegex(@"[A-Za-z0-9+/]{4,}={0,2}", RegexOptions.Compiled)]
    private static partial Regex Base64Pattern();

    [GeneratedRegex(@"\\x([0-9a-fA-F]{2})", RegexOptions.Compiled)]
    private static partial Regex HexPattern();
}
