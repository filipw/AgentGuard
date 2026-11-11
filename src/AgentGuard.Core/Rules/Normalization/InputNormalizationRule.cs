using System.Buffers;
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
    /// cannot see ("ASCII smuggling"). Besides being stripped, what they spell is handed on as a
    /// decoded view, like the other decoders' output, so downstream rules can inspect it.
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
/// </summary>
/// <remarks>
/// <para>
/// Unicode normalization and invisible-character stripping rewrite the text itself. What the decoders
/// find (base64, hex, reversed text, leetspeak, Unicode tags, compatibility forms) is never written into
/// the text - the model receives the message as the user wrote it. The decoded views are handed to the
/// pipeline under <see cref="DecodedViewsKey"/>, and <see cref="Guardrails.GuardrailPipeline"/> runs
/// every later rule over them as well, for detection only: a block found in a decoded view blocks the
/// message, a rewrite of one is discarded.
/// </para>
/// <para>
/// Informed by the Arcanum Prompt Injection Taxonomy evasion categories.
/// </para>
/// </remarks>
public sealed partial class InputNormalizationRule : IGuardrailRule
{
    /// <summary>
    /// The <see cref="GuardrailContext.Properties"/> key under which the rule hands its decoded views
    /// (an <see cref="IReadOnlyList{T}"/> of <see cref="string"/>) to the pipeline.
    /// </summary>
    public const string DecodedViewsKey = "AgentGuard.DecodedViews";

    /// <summary>
    /// The <see cref="GuardrailContext.Properties"/> key present (with the value <c>true</c>) when a rule
    /// is evaluating the decoded views rather than the text the model receives. Rules that measure the
    /// text itself rather than look for content in it, such as token limits, skip such an evaluation.
    /// </summary>
    public const string DecodedViewKey = "AgentGuard.IsDecodedView";

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

        // the decoded views are for the rules, not the model: they go to the pipeline beside the text,
        // never into it, so a payload no rule recognizes is not delivered to the model already decoded
        if (decodedSegments.Count > 0)
            context.Properties[DecodedViewsKey] = (IReadOnlyList<string>)decodedSegments;

        var normalizationChanged = !string.Equals(text, context.Text, StringComparison.Ordinal);

        return ValueTask.FromResult(normalizationChanged
            ? GuardrailResult.Modified(text, "Input contained hidden or disguised characters that were normalized.")
            : GuardrailResult.Passed());
    }

    /// <summary>
    /// Finds base64-encoded segments and attempts to decode them. Standard and URL-safe alphabets
    /// are read, with or without padding. Returns the decoded text if readable text was found, null
    /// otherwise.
    /// </summary>
    internal string? DecodeBase64Segments(string text)
    {
        var matches = Base64Pattern().Matches(text);
        if (matches.Count == 0)
            return null;

        var decodedParts = new List<string>();
        foreach (Match match in matches)
        {
            var candidate = match.Value;
            if (candidate.Length < _options.MinBase64Length)
                continue;

            if (TryDecodeBase64(candidate) is { } whole)
            {
                decodedParts.Add(whole);
                continue;
            }

            // '-' and '_' are base64 only in the URL-safe alphabet; elsewhere they join a payload to
            // its neighbours (payload-aWdub3Jl..., key_aWdub3Jl...), so the pieces are tried on their own
            if (candidate.AsSpan().IndexOfAny('-', '_') < 0)
                continue;

            foreach (var piece in candidate.Split(Base64Joiners, StringSplitOptions.RemoveEmptyEntries))
            {
                if (piece.Length >= _options.MinBase64Length && TryDecodeBase64(piece) is { } part)
                    decodedParts.Add(part);
            }
        }

        return decodedParts.Count > 0 ? string.Join(" ", decodedParts) : null;
    }

    private static readonly char[] Base64Joiners = ['-', '_'];

    private static string? TryDecodeBase64(string candidate)
    {
        var body = candidate.TrimEnd('=').Replace('-', '+').Replace('_', '/');

        // a length of 4n+1 is never valid base64: the last character belongs to whatever follows
        if (body.Length % 4 == 1)
            body = body[..^1];

        var padded = (body.Length % 4) switch
        {
            2 => body + "==",
            3 => body + "=",
            _ => body
        };

        var buffer = new byte[padded.Length / 4 * 3];
        if (!Convert.TryFromBase64String(padded, buffer, out var written))
            return null;

        var decoded = Encoding.UTF8.GetString(buffer, 0, written);

        // only readable text counts (mostly printable ASCII); anything else was not an encoded message
        return IsPrintableText(decoded) ? decoded : null;
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
    /// Detects reversed text and returns it read forwards, or null when nothing was reversed.
    /// </summary>
    /// <remarks>
    /// Text counts as reversed when reading it backwards yields clearly more common words than
    /// reading it forwards, or when at least two of its words are injection vocabulary spelled
    /// backwards - which also finds a reversed instruction behind a plain-text preamble. Both ways of
    /// reversing are undone: the whole text read backwards, and each reversed word turned round in
    /// place.
    /// </remarks>
    internal static string? DetectAndReverseText(string text)
    {
        var words = SplitWords(text);
        if (words.Length < 2)
            return null;

        // reversed by code point: reversing UTF-16 units would turn every surrogate pair into two lone surrogates
        var runes = text.EnumerateRunes().ToArray();
        Array.Reverse(runes);
        var reversed = ToText(runes);

        var reversedVocabulary = 0;
        foreach (var word in words)
        {
            var core = TrimWord(word);
            if (core.Length >= MinVocabularyWordLength
                && !IsKnownWord(core)
                && InjectionVocabulary.Contains(ReverseWord(core)))
            {
                reversedVocabulary++;
            }
        }

        var readsBetterBackwards = CountKnownWords(reversed) > CountKnownWords(text) + 2;
        if (!readsBetterBackwards && reversedVocabulary < 2)
            return null;

        // the whole text backwards restores a message reversed end to end; turning single words round
        // restores one whose words were reversed in place. Which of the two was done cannot be told
        // from the words alone, so a view carries both whenever they differ.
        var wordwise = ReverseUnknownWords(text);
        return wordwise is null || string.Equals(wordwise, reversed, StringComparison.Ordinal)
            ? reversed
            : reversed + "\n" + wordwise;
    }

    // Turns round each word that only reads as a known word backwards; other words stay as written.
    private static string? ReverseUnknownWords(string text)
    {
        StringBuilder? result = null;
        var index = 0;
        while (index < text.Length)
        {
            if (char.IsWhiteSpace(text[index]))
            {
                result?.Append(text[index]);
                index++;
                continue;
            }

            var end = index;
            while (end < text.Length && !char.IsWhiteSpace(text[end]))
                end++;

            var word = text[index..end];
            var core = TrimWord(word);
            var turned = core.Length >= 2 && !IsKnownWord(core) ? ReverseWord(core) : null;
            if (turned is not null && IsKnownWord(turned))
            {
                result ??= new StringBuilder(text.Length).Append(text, 0, index);
                result.Append(word.Replace(core, turned, StringComparison.Ordinal));
            }
            else
            {
                result?.Append(word);
            }

            index = end;
        }

        return result?.ToString();
    }

    private static string ReverseWord(string word)
    {
        var runes = word.EnumerateRunes().ToArray();
        Array.Reverse(runes);
        return ToText(runes).ToLowerInvariant();
    }

    private static string TrimWord(string word) => word.Trim(WordPunctuation);

    private static bool IsKnownWord(string word)
    {
        var lower = word.ToLowerInvariant();
        return CommonWords.Contains(lower) || InjectionVocabulary.Contains(lower);
    }

    private static readonly char[] WordPunctuation =
        ['.', ',', '!', '?', ';', ':', '"', '\'', '(', ')', '[', ']', '{', '}', '<', '>', '*', '`'];

    // shorter words turn up by accident in ordinary text when it is decoded
    private const int MinVocabularyWordLength = 4;

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

            // an emoji variation selector presents the few enclosed letters that double as emoji (the
            // parking sign, the blood types, the metro sign) as an emoji; after any other styled
            // letter it is padding, and must not keep the letter from being folded
            var isEmoji = HasEmojiPresentation(value)
                && i + 1 < runes.Length && runes[i + 1].Value == EmojiVariationSelector;
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

    // Ⓜ and the negative squared A, B, O and P
    private static bool HasEmojiPresentation(int value) => value is 0x24C2 or 0x1F170 or 0x1F171 or 0x1F17E or 0x1F17F;

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
    /// Strips the Unicode characters that render as nothing and are used to break up words: zero-width
    /// and joiner characters, directional marks, embeddings, overrides and isolates, invisible
    /// operators, soft hyphens, Hangul fillers, Unicode tag characters (U+E0000-U+E007F), and
    /// variation selectors placed after a letter or digit. Returns null if there were none.
    /// </summary>
    /// <remarks>
    /// Walks the text by code point: tag characters and the supplementary variation selectors are
    /// surrogate pairs, which a per-char loop never recognises. A variation selector that follows a
    /// symbol, an emoji or an ideograph selects how that character is drawn and is kept, as is the
    /// one inside a keycap sequence (digit, U+FE0F, U+20E3).
    /// </remarks>
    internal static string? StripInvisibleCharacters(string text)
    {
        if (Ascii.IsValid(text))
            return null;

        StringBuilder? builder = null;
        var span = text.AsSpan();
        var index = 0;
        Rune? previousKept = null;

        while (index < span.Length)
        {
            var status = Rune.DecodeFromUtf16(span[index..], out var rune, out var consumed);
            var remove = false;

            if (status == OperationStatus.Done)
            {
                if (IsVariationSelector(rune.Value))
                {
                    remove = previousKept is not { } previous
                        || IsAlphabeticLetter(previous)
                        || (previous.Value is >= '0' and <= '9' or '#' or '*'
                            && !IsKeycapMark(span[(index + consumed)..]));
                }
                else
                {
                    remove = IsInvisibleCharacter(rune);
                }
            }

            if (remove)
            {
                // first removal: copy everything kept so far, then keep appending from here on
                builder ??= new StringBuilder(text.Length).Append(text, 0, index);
            }
            else
            {
                builder?.Append(text, index, consumed);
                if (status == OperationStatus.Done)
                    previousKept = rune;
            }

            index += consumed;
        }

        return builder?.ToString();
    }

    private static bool IsKeycapMark(ReadOnlySpan<char> rest) => rest.Length > 0 && rest[0] == '⃣';

    // U+FE00-U+FE0F and the supplement U+E0100-U+E01EF
    private static bool IsVariationSelector(int value) =>
        value is (>= 0xFE00 and <= 0xFE0F) or (>= 0xE0100 and <= 0xE01EF);

    // letters of the alphabetic scripts, which take no variation selector; ideographs, which do, are
    // "other letters"
    private static bool IsAlphabeticLetter(Rune rune) => Rune.GetUnicodeCategory(rune) is
        UnicodeCategory.UppercaseLetter or UnicodeCategory.LowercaseLetter or UnicodeCategory.TitlecaseLetter
        or UnicodeCategory.ModifierLetter;

    private static bool IsInvisibleCharacter(Rune rune) =>
        InvisibleCharacters.IsUnicodeTag(rune) || (rune.IsBmp && IsInvisibleCharacter((char)rune.Value));

    private static bool IsInvisibleCharacter(char c) => c switch
    {
        '​' => true, // Zero-width space
        '‌' => true, // Zero-width non-joiner
        '‍' => true, // Zero-width joiner
        '‎' => true, // Left-to-right mark
        '‏' => true, // Right-to-left mark
        >= '‪' and <= '‮' => true, // Directional embeddings and overrides
        '⁠' => true, // Word joiner
        '⁡' => true, // Function application
        '⁢' => true, // Invisible times
        '⁣' => true, // Invisible separator
        '⁤' => true, // Invisible plus
        >= '⁦' and <= '⁩' => true, // Directional isolates
        '﻿' => true, // BOM / zero-width no-break space
        '­' => true, // Soft hyphen
        '͏' => true, // Combining grapheme joiner
        '؜' => true, // Arabic letter mark
        'ᅟ' => true, // Hangul choseong filler
        'ᅠ' => true, // Hangul jungseong filler
        '឴' => true, // Khmer vowel inherent AQ
        '឵' => true, // Khmer vowel inherent AA
        '᠎' => true, // Mongolian vowel separator
        'ㅤ' => true, // Hangul filler
        'ﾠ' => true, // Halfwidth Hangul filler
        _ => false
    };

    /// <summary>
    /// Decodes common leetspeak substitutions (1gn0r3 → ignore), or returns null when doing so
    /// reveals nothing.
    /// </summary>
    /// <remarks>
    /// Only words that mix letters with substitute characters are decoded, so numbers, prices and
    /// punctuation stay as written. The decoded text is reported when a decoded word is injection
    /// vocabulary, or when decoding reveals several common words at once. A <c>1</c> stands for
    /// <c>i</c> or <c>l</c>, whichever spells a known word.
    /// </remarks>
    internal static string? DecodeLeetspeak(string text)
    {
        StringBuilder? decoded = null;
        var revealedVocabulary = 0;
        var index = 0;

        while (index < text.Length)
        {
            if (char.IsWhiteSpace(text[index]))
            {
                decoded?.Append(text[index]);
                index++;
                continue;
            }

            var end = index;
            while (end < text.Length && !char.IsWhiteSpace(text[end]))
                end++;

            var word = text.AsSpan(index, end - index);
            var plain = DecodeLeetWord(word);
            if (plain is null)
            {
                decoded?.Append(word);
            }
            else
            {
                decoded ??= new StringBuilder(text.Length).Append(text, 0, index);
                decoded.Append(plain);

                var core = TrimWord(plain).ToLowerInvariant();
                if (core.Length >= MinVocabularyWordLength && InjectionVocabulary.Contains(core))
                    revealedVocabulary++;
            }

            index = end;
        }

        if (decoded is null)
            return null;

        var decodedText = decoded.ToString();
        if (revealedVocabulary > 0)
            return decodedText;

        return CountKnownWords(decodedText) > CountKnownWords(text) + 1 ? decodedText : null;
    }

    // Decodes one word, or returns null when it holds no substitution or no letter to anchor one.
    private static string? DecodeLeetWord(ReadOnlySpan<char> word)
    {
        var hasLetter = false;
        var substitutes = 0;
        var ones = 0;
        for (var i = 0; i < word.Length; i++)
        {
            var c = word[i];
            if (char.IsAsciiLetter(c))
            {
                hasLetter = true;
            }
            else if (IsLeetSubstitute(word, i))
            {
                substitutes++;
                if (c == '1')
                    ones++;
            }
        }

        if (!hasLetter || substitutes == 0)
            return null;

        // every 1 as i first; then the other readings, as long as there are few enough to try
        var buffer = new char[word.Length];
        var readings = ones is > 0 and <= MaxAmbiguousOnes ? 1 << ones : 1;
        string? first = null;
        for (var reading = 0; reading < readings; reading++)
        {
            var one = 0;
            for (var i = 0; i < word.Length; i++)
            {
                var c = word[i];
                if (!IsLeetSubstitute(word, i))
                    buffer[i] = c;
                else if (c == '1')
                    buffer[i] = (reading >> one++ & 1) == 0 ? 'i' : 'l';
                else
                    buffer[i] = LeetMap[c];
            }

            var candidate = new string(buffer);
            first ??= candidate;
            if (IsKnownWord(TrimWord(candidate)))
                return candidate;
        }

        return first;
    }

    // '!' ends far more sentences than it replaces an i, so it only counts inside a word
    private static bool IsLeetSubstitute(ReadOnlySpan<char> word, int index)
    {
        var c = word[index];
        if (!LeetMap.ContainsKey(c))
            return false;

        return c != '!' || (index + 1 < word.Length && char.IsAsciiLetterOrDigit(word[index + 1]));
    }

    private const int MaxAmbiguousOnes = 4;

    // Common leetspeak substitutions
    private static readonly FrozenDictionary<char, char> LeetMap = new Dictionary<char, char>
    {
        ['0'] = 'o',
        ['1'] = 'i',
        ['3'] = 'e',
        ['4'] = 'a',
        ['5'] = 's',
        ['7'] = 't',
        ['@'] = 'a',
        ['!'] = 'i',
        ['$'] = 's',
    }.ToFrozenDictionary();

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
            if (CommonWords.Contains(TrimWord(word).ToLowerInvariant()))
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

    // What an injection is written with. One of these appearing only once the text is decoded is
    // enough to hand the decoded text to the detection rules.
    private static readonly FrozenSet<string> InjectionVocabulary = FrozenSet.ToFrozenSet(
    [
        "ignore", "ignoring", "disregard", "forget", "override", "bypass", "disable", "circumvent",
        "previous", "prior", "above", "earlier", "preceding",
        "instruction", "instructions", "directive", "directives", "rules", "guidelines", "restrictions",
        "limitations", "policies", "safeguards", "safety", "filter", "filters", "guardrails",
        "system", "prompt", "prompts", "developer", "admin", "administrator",
        "pretend", "roleplay", "simulate", "jailbreak", "unrestricted", "unfiltered", "uncensored",
        "reveal", "secret", "secrets", "confidential", "hidden", "password", "passwords", "credentials",
        "obey", "comply", "execute",
    ]);

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

    [GeneratedRegex(@"[A-Za-z0-9+/_\-]{4,}={0,2}", RegexOptions.Compiled)]
    private static partial Regex Base64Pattern();

    [GeneratedRegex(@"\\x([0-9a-fA-F]{2})", RegexOptions.Compiled)]
    private static partial Regex HexPattern();
}
