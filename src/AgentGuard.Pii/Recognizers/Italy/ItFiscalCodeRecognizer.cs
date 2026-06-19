using AgentGuard.Pii.Analyzer;

namespace AgentGuard.Pii.Recognizers.Italy;

/// <summary>
/// Recognizes the Italian fiscal code (Codice Fiscale) using regex plus the alphabetic mod-26 control
/// character. A matching control character promotes the score; a mismatch keeps the base score.
/// </summary>
public sealed class ItFiscalCodeRecognizer : PatternRecognizer
{
    private static readonly IReadOnlyList<Pattern> DefaultPatterns =
    [
        new Pattern(
            "Fiscal Code",
            @"(?i)((?:[A-Z][AEIOU][AEIOUX]|[AEIOU]X{2}|[B-DF-HJ-NP-TV-Z]{2}[A-Z]){2}(?:[\dLMNP-V]{2}(?:[A-EHLMPR-T](?:[04LQ][1-9MNP-V]|[15MR][\dLMNP-V]|[26NS][0-8LMNP-U])|[DHPS][37PT][0L]|[ACELMRT][37PT][01LM]|[AC-EHLMPR-T][26NS][9V])|(?:[02468LNQSU][048LQU]|[13579MPRTV][26NS])B[26NS][9V])(?:[A-MZ][1-9MNP-V][\dLMNP-V]{2}|[A-M][0L](?:[1-9MNP-V][\dLMNP-V]|[0L][1-9MNP-V]))[A-Z])",
            0.3),
    ];

    private static readonly IReadOnlyList<string> DefaultContext = ["codice fiscale", "cf"];

    private static readonly Dictionary<char, int> OddValues = new()
    {
        ['0'] = 1, ['1'] = 0, ['2'] = 5, ['3'] = 7, ['4'] = 9, ['5'] = 13, ['6'] = 15, ['7'] = 17,
        ['8'] = 19, ['9'] = 21, ['A'] = 1, ['B'] = 0, ['C'] = 5, ['D'] = 7, ['E'] = 9, ['F'] = 13,
        ['G'] = 15, ['H'] = 17, ['I'] = 19, ['J'] = 21, ['K'] = 2, ['L'] = 4, ['M'] = 18, ['N'] = 20,
        ['O'] = 11, ['P'] = 3, ['Q'] = 6, ['R'] = 8, ['S'] = 12, ['T'] = 14, ['U'] = 16, ['V'] = 10,
        ['W'] = 22, ['X'] = 25, ['Y'] = 24, ['Z'] = 23,
    };

    /// <summary>Initializes a new instance of the <see cref="ItFiscalCodeRecognizer"/> class.</summary>
    public ItFiscalCodeRecognizer(string supportedEntity = "IT_FISCAL_CODE", string supportedLanguage = "en")
        : base(supportedEntity, patterns: DefaultPatterns, context: DefaultContext, supportedLanguage: supportedLanguage, countryCode: "it")
    {
    }

    /// <inheritdoc />
    public override bool? ValidateResult(string patternText)
    {
        var text = patternText.ToUpperInvariant();
        if (text.Length < 2)
        {
            return null;
        }

        var control = text[^1];
        var body = text[..^1];

        var sum = 0;
        for (var i = 0; i < body.Length; i++)
        {
            var c = body[i];
            if (i % 2 == 0)
            {
                // odd position (1-based)
                if (!OddValues.TryGetValue(c, out var odd))
                {
                    return null;
                }

                sum += odd;
            }
            else
            {
                // even position (1-based): digit face value, or letter A=0..Z=25
                sum += c is >= '0' and <= '9' ? c - '0' : c - 'A';
            }
        }

        var checkValue = (char)('A' + (sum % 26));
        return checkValue == control ? true : null;
    }
}
