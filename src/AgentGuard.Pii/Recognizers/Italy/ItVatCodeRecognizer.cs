using AgentGuard.Pii.Analyzer;

namespace AgentGuard.Pii.Recognizers.Italy;

/// <summary>
/// Recognizes the Italian VAT code (Partita IVA, 11 digits) using regex plus its Luhn-style check digit.
/// </summary>
public sealed class ItVatCodeRecognizer : PatternRecognizer
{
    private static readonly IReadOnlyList<Pattern> DefaultPatterns =
    [
        new Pattern("IT Vat code (piva)", @"\b([0-9][ _]?){11}\b", 0.1),
    ];

    private static readonly IReadOnlyList<string> DefaultContext = ["piva", "partita iva", "pi"];

    private static readonly IReadOnlyList<(string, string)> ReplacementPairs = [("-", ""), (" ", ""), ("_", "")];

    /// <summary>Initializes a new instance of the <see cref="ItVatCodeRecognizer"/> class.</summary>
    public ItVatCodeRecognizer(string supportedEntity = "IT_VAT_CODE", string supportedLanguage = "en")
        : base(supportedEntity, patterns: DefaultPatterns, context: DefaultContext, supportedLanguage: supportedLanguage, countryCode: "it")
    {
    }

    /// <inheritdoc />
    public override bool? ValidateResult(string patternText)
    {
        var text = SanitizeValue(patternText, ReplacementPairs);
        if (text.Length != 11 || !text.All(char.IsDigit))
        {
            return false;
        }

        // an all-zero value passes the checksum arithmetic but is not a valid VAT code
        if (text == "00000000000")
        {
            return false;
        }

        var x = 0;
        var y = 0;
        for (var i = 0; i < 5; i++)
        {
            x += text[2 * i] - '0';
            var tmp = (text[(2 * i) + 1] - '0') * 2;
            if (tmp > 9)
            {
                tmp -= 9;
            }

            y += tmp;
        }

        var t = (x + y) % 10;
        var c = (10 - t) % 10;
        return c == text[10] - '0';
    }
}
