using AgentGuard.Pii.Analyzer;

namespace AgentGuard.Pii.Recognizers.Us;

/// <summary>
/// Recognizes US DEA medical license numbers using regex plus the DEA registration checksum.
/// </summary>
public sealed class MedicalLicenseRecognizer : PatternRecognizer
{
    private static readonly IReadOnlyList<Pattern> DefaultPatterns =
    [
        new Pattern(
            "USA DEA Certificate Number (weak)",
            @"[abcdefghjklmprstuxABCDEFGHJKLMPRSTUX]{1}[a-zA-Z]{1}\d{7}|[abcdefghjklmprstuxABCDEFGHJKLMPRSTUX]{1}9\d{7}",
            0.4),
    ];

    private static readonly IReadOnlyList<string> DefaultContext = ["medical", "certificate", "DEA"];

    private static readonly IReadOnlyList<(string, string)> ReplacementPairs = [("-", ""), (" ", "")];

    /// <summary>Initializes a new instance of the <see cref="MedicalLicenseRecognizer"/> class.</summary>
    public MedicalLicenseRecognizer(string supportedEntity = "MEDICAL_LICENSE", string supportedLanguage = "en")
        : base(supportedEntity, patterns: DefaultPatterns, context: DefaultContext, supportedLanguage: supportedLanguage, countryCode: "us")
    {
    }

    /// <inheritdoc />
    public override bool? ValidateResult(string patternText)
    {
        var value = SanitizeValue(patternText, ReplacementPairs);

        // DEA number: 2 letters followed by 7 digits; the trailing digit is a check digit
        var digits = value.Length >= 2 ? value[2..] : string.Empty;
        if (digits.Length != 7 || !digits.All(char.IsDigit))
        {
            return false;
        }

        var d = digits.Select(c => c - '0').ToArray();
        var check = d[6];
        // check digit = (d1 + d3 + d5) + 2 * (d2 + d4 + d6), mod 10
        var sumOdd = d[0] + d[2] + d[4];
        var sumEven = d[1] + d[3] + d[5];
        return (sumOdd + (2 * sumEven)) % 10 == check;
    }
}
