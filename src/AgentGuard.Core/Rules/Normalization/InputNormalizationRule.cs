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

    /// <summary>Whether to normalize Unicode homoglyphs (e.g. Cyrillic а → Latin a). Default: true.</summary>
    public bool NormalizeUnicode { get; init; } = true;

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

        var decodedSegments = new List<string>();
        var text = context.Text;

        if (_options.NormalizeUnicode)
        {
            var normalized = NormalizeUnicode(text);
            if (normalized != text)
            {
                text = normalized;
                decodedSegments.Add(normalized);
            }
        }

        if (_options.DecodeBase64)
        {
            var decoded = DecodeBase64Segments(text);
            if (decoded is not null)
                decodedSegments.Add(decoded);
        }

        if (_options.DecodeHex)
        {
            var decoded = DecodeHexSequences(text);
            if (decoded is not null)
                decodedSegments.Add(decoded);
        }

        if (_options.DetectReversedText)
        {
            var reversed = DetectAndReverseText(text);
            if (reversed is not null)
                decodedSegments.Add(reversed);
        }

        if (decodedSegments.Count == 0)
            return ValueTask.FromResult(GuardrailResult.Passed());

        // Append decoded content so downstream rules can evaluate both original and decoded forms
        var combined = text + "\n[DECODED]\n" + string.Join("\n", decodedSegments);
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
        var words = text.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (words.Length < 2)
            return null;

        var reversed = new string(text.Reverse().ToArray());

        var originalHits = CountKnownWords(text);
        var reversedHits = CountKnownWords(reversed);

        // If the reversed version has significantly more recognizable words, it was likely reversed
        return reversedHits > originalHits + 2 ? reversed : null;
    }

    /// <summary>
    /// Normalizes Unicode homoglyphs to their ASCII equivalents.
    /// Catches attacks using Cyrillic/Greek characters that visually resemble Latin characters.
    /// </summary>
    internal static string NormalizeUnicode(string text)
    {
        // First, apply NFC normalization to handle combining characters
        var normalized = text.Normalize(NormalizationForm.FormKC);

        // Then replace common homoglyphs
        var sb = new StringBuilder(normalized.Length);
        foreach (var c in normalized)
        {
            sb.Append(HomoglyphMap.TryGetValue(c, out var replacement) ? replacement : c);
        }

        return sb.ToString();
    }

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
        var words = text.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var count = 0;
        foreach (var word in words)
        {
            if (CommonWords.Contains(word.Trim('.', ',', '!', '?', ';', ':').ToLowerInvariant()))
                count++;
        }
        return count;
    }

    // Words commonly found in prompt injection attacks when reversed
    private static readonly HashSet<string> CommonWords =
    [
        "ignore", "previous", "instructions", "system", "prompt", "override",
        "forget", "disregard", "pretend", "rules", "new", "now", "you", "are",
        "the", "all", "your", "show", "tell", "me", "what", "how", "is", "do",
        "act", "as", "if", "a", "an", "and", "or", "not", "no", "be", "to",
        "this", "that", "it", "in", "for", "with", "on", "from", "but",
    ];

    // Common Cyrillic/Greek → Latin homoglyph mappings
    private static readonly Dictionary<char, char> HomoglyphMap = new()
    {
        // Cyrillic
        ['а'] = 'a', ['А'] = 'A',
        ['с'] = 'c', ['С'] = 'C',
        ['е'] = 'e', ['Е'] = 'E',
        ['о'] = 'o', ['О'] = 'O',
        ['р'] = 'p', ['Р'] = 'P',
        ['х'] = 'x', ['Х'] = 'X',
        ['у'] = 'y', ['У'] = 'Y',
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
        ['ν'] = 'v',
        ['τ'] = 't', ['Τ'] = 'T',
    };

    [GeneratedRegex(@"[A-Za-z0-9+/]{4,}={0,2}", RegexOptions.Compiled)]
    private static partial Regex Base64Pattern();

    [GeneratedRegex(@"\\x([0-9a-fA-F]{2})", RegexOptions.Compiled)]
    private static partial Regex HexPattern();
}
