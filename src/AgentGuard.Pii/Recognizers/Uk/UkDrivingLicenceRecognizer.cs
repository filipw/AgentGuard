using System.Text.RegularExpressions;
using AgentGuard.Pii.Analyzer;

namespace AgentGuard.Pii.Recognizers.Uk;

/// <summary>
/// Recognizes UK DVLA driving licence numbers (16-character structured format) using regex. The DVLA
/// check-digit algorithm is not public, so validation can only reject clearly invalid surnames.
/// </summary>
public sealed partial class UkDrivingLicenceRecognizer : PatternRecognizer
{
    private static readonly IReadOnlyList<Pattern> DefaultPatterns =
    [
        new Pattern(
            "UK Driving Licence",
            @"\b[A-Z9]{5}[0-9](?:0[1-9]|1[0-2]|5[1-9]|6[0-2])(?:0[1-9]|[12][0-9]|3[01])[0-9][A-Z9]{2}[A-Z0-9][A-Z]{2}\b",
            0.5),
    ];

    private static readonly IReadOnlyList<string> DefaultContext =
    [
        "driving licence", "driving license", "driver's licence", "driver's license", "dvla",
        "dl number", "licence number", "license number",
    ];

    /// <summary>Initializes a new instance of the <see cref="UkDrivingLicenceRecognizer"/> class.</summary>
    public UkDrivingLicenceRecognizer(string supportedEntity = "UK_DRIVING_LICENCE", string supportedLanguage = "en")
        : base(supportedEntity, patterns: DefaultPatterns, context: DefaultContext, supportedLanguage: supportedLanguage, countryCode: "uk")
    {
    }

    /// <inheritdoc />
    public override bool? ValidateResult(string patternText)
    {
        var text = patternText.ToUpperInvariant();
        if (text.Length < 5)
        {
            return false;
        }

        var surname = text[..5];

        // an all-9 surname portion is never valid; otherwise the surname must be letters then trailing 9-padding only
        if (surname == "99999" || !SurnameRegex().IsMatch(surname))
        {
            return false;
        }

        // the DVLA check-digit algorithm is not public; cannot confirm validity, only reject
        return null;
    }

    [GeneratedRegex(@"^[A-Z]+9*$")]
    private static partial Regex SurnameRegex();
}
