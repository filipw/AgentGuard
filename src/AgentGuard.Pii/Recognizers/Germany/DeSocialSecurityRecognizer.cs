using System.Text.RegularExpressions;
using AgentGuard.Pii.Analyzer;

namespace AgentGuard.Pii.Recognizers.Germany;

/// <summary>
/// Recognizes the German Rentenversicherungsnummer (12-character pension insurance id) using regex
/// plus the digit-cross-sum check digit and birth date structural validation.
/// </summary>
public sealed partial class DeSocialSecurityRecognizer : PatternRecognizer
{
    private static readonly IReadOnlyList<Pattern> DefaultPatterns =
    [
        new Pattern(
            "Rentenversicherungsnummer (strict)",
            @"\b\d{2}(0[1-9]|[12]\d|3[01]|5[1-9]|[67]\d|8[01])(0[1-9]|1[0-2])\d{2}[A-Z]\d{2}[0-9]\b",
            0.5),
        new Pattern("Rentenversicherungsnummer (relaxed)", @"\b\d{8}[A-Z]\d{3}\b", 0.3),
    ];

    private static readonly IReadOnlyList<string> DefaultContext =
    [
        "rentenversicherungsnummer", "sozialversicherungsnummer", "versicherungsnummer", "rvnr",
        "svnr", "sv-nummer", "rente", "rentenversicherung", "deutsche rentenversicherung", "drv",
        "sozialversicherung", "sozialversicherungsausweis", "rentenausweis",
    ];

    private static readonly int[] Weights = [2, 1, 2, 5, 7, 1, 2, 1, 2, 1, 2, 1];

    /// <summary>Initializes a new instance of the <see cref="DeSocialSecurityRecognizer"/> class.</summary>
    public DeSocialSecurityRecognizer(string supportedEntity = "DE_SOCIAL_SECURITY", string supportedLanguage = "en")
        : base(supportedEntity, patterns: DefaultPatterns, context: DefaultContext, supportedLanguage: supportedLanguage, countryCode: "de")
    {
    }

    /// <inheritdoc />
    public override bool? ValidateResult(string patternText)
    {
        var text = patternText.ToUpperInvariant().Trim();
        if (text.Length != 12 || !StructureRegex().IsMatch(text))
        {
            return false;
        }

        // birth day (01-31, or 51-81 with +50 supplement) and month (01-12) are structural invariants
        var day = int.Parse(text[2..4], System.Globalization.CultureInfo.InvariantCulture);
        var month = int.Parse(text[4..6], System.Globalization.CultureInfo.InvariantCulture);
        if (!((day is >= 1 and <= 31) || (day is >= 51 and <= 81)) || month is < 1 or > 12)
        {
            return false;
        }

        // replace the surname letter with its two-digit ordinal (A=01..Z=26), yielding twelve data digits
        var letterValue = (text[8] - 'A' + 1).ToString("D2", System.Globalization.CultureInfo.InvariantCulture);
        var effective = text[..8] + letterValue + text[9..11];
        var checkDigit = text[11] - '0';

        var total = 0;
        for (var i = 0; i < effective.Length; i++)
        {
            var product = (effective[i] - '0') * Weights[i];
            total += (product / 10) + (product % 10);
        }

        return total % 10 == checkDigit;
    }

    [GeneratedRegex(@"^\d{8}[A-Z]\d{3}$")]
    private static partial Regex StructureRegex();
}
