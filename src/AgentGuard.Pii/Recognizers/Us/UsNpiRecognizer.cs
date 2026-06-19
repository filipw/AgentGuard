using AgentGuard.Pii.Analyzer;

namespace AgentGuard.Pii.Recognizers.Us;

/// <summary>
/// Recognizes US National Provider Identifiers (NPI) using regex plus a Luhn checksum computed over
/// the CMS "80840" prefixed value.
/// </summary>
public sealed class UsNpiRecognizer : PatternRecognizer
{
    private static readonly IReadOnlyList<Pattern> DefaultPatterns =
    [
        new Pattern("NPI (weak)", @"\b[12]\d{9}\b", 0.1),
        new Pattern("NPI (medium)", @"\b[12]\d{3}[ -]\d{3}[ -]\d{3}\b", 0.4),
    ];

    private static readonly IReadOnlyList<string> DefaultContext =
    [
        "npi", "national provider", "provider", "npi number", "provider id",
        "provider identifier", "taxonomy",
    ];

    private static readonly IReadOnlyList<(string, string)> ReplacementPairs = [("-", ""), (" ", "")];

    /// <summary>Initializes a new instance of the <see cref="UsNpiRecognizer"/> class.</summary>
    public UsNpiRecognizer(string supportedEntity = "US_NPI", string supportedLanguage = "en")
        : base(supportedEntity, patterns: DefaultPatterns, context: DefaultContext, supportedLanguage: supportedLanguage, countryCode: "us")
    {
    }

    /// <inheritdoc />
    public override bool? ValidateResult(string patternText)
    {
        var value = SanitizeValue(patternText, ReplacementPairs);
        if (value.Length == 0 || !value.All(char.IsDigit))
        {
            return false;
        }

        // prepend the CMS "80840" namespace prefix then run a standard Luhn checksum
        var prefixed = "80840" + value;
        var checksum = 0;
        for (var i = 0; i < prefixed.Length; i++)
        {
            var digit = prefixed[prefixed.Length - 1 - i] - '0';
            if (i % 2 == 1)
            {
                var doubled = digit * 2;
                checksum += doubled > 9 ? doubled - 9 : doubled;
            }
            else
            {
                checksum += digit;
            }
        }

        return checksum % 10 == 0;
    }

    /// <inheritdoc />
    public override bool? InvalidateResult(string patternText)
    {
        var value = SanitizeValue(patternText, ReplacementPairs);
        if (value.Length <= 1)
        {
            return null;
        }

        // reject degenerate patterns where every body digit is identical
        var body = value[..^1];
        return body.All(c => c == body[0]) ? true : null;
    }
}
