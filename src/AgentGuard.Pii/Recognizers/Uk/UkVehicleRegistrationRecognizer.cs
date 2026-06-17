using AgentGuard.Pii.Analyzer;

namespace AgentGuard.Pii.Recognizers.Uk;

/// <summary>
/// Recognizes UK vehicle registration numbers across the current, prefix and suffix formats using
/// regex. The current format is further validated by its two-digit age identifier range.
/// </summary>
public sealed class UkVehicleRegistrationRecognizer : PatternRecognizer
{
    private static readonly IReadOnlyList<Pattern> DefaultPatterns =
    [
        new Pattern(
            "UK Vehicle Registration (current)",
            @"\b[A-HJ-PR-Y][A-HJ-PR-Y](?:0[1-9]|[1-7][0-9])[- ]?[A-HJ-PR-Z]{3}\b",
            0.3),
        new Pattern(
            "UK Vehicle Registration (prefix)",
            @"\b[A-HJ-NPR-TV-Y]\d{1,3}[- ]?[A-HJ-PR-Y][A-HJ-PR-Z]{2}\b",
            0.2),
        new Pattern(
            "UK Vehicle Registration (suffix)",
            @"\b[A-HJ-PR-Z]{3}[- ]?\d{1,3}[- ]?[A-HJ-NPR-TV-Y]\b",
            0.15),
    ];

    private static readonly IReadOnlyList<string> DefaultContext =
    [
        "vehicle", "registration", "number plate", "licence plate", "license plate", "reg", "vrn",
        "dvla", "v5c", "logbook", "mot", "car", "insured vehicle",
    ];

    private static readonly IReadOnlyList<(string, string)> ReplacementPairs = [("-", ""), (" ", "")];

    /// <summary>Initializes a new instance of the <see cref="UkVehicleRegistrationRecognizer"/> class.</summary>
    public UkVehicleRegistrationRecognizer(string supportedEntity = "UK_VEHICLE_REGISTRATION", string supportedLanguage = "en")
        : base(supportedEntity, patterns: DefaultPatterns, context: DefaultContext, supportedLanguage: supportedLanguage, countryCode: "uk")
    {
    }

    /// <inheritdoc />
    public override bool? ValidateResult(string patternText)
    {
        var value = SanitizeValue(patternText, ReplacementPairs);

        // only the current format (7 chars, two leading letters) carries a validatable age identifier
        if (value.Length == 7 && char.IsLetter(value[0]) && char.IsLetter(value[1]))
        {
            var ageId = value[2..4];
            if (ageId.All(char.IsDigit))
            {
                var age = int.Parse(ageId, System.Globalization.CultureInfo.InvariantCulture);
                return (age is >= 2 and <= 29) || (age is >= 51 and <= 79);
            }
        }

        // prefix/suffix formats keep their base pattern score
        return null;
    }
}
