using AgentGuard.Pii.Analyzer;

namespace AgentGuard.Pii.Recognizers.Us;

/// <summary>
/// Recognizes US driver license numbers using regex covering the various state formats.
/// </summary>
public sealed class UsDriverLicenseRecognizer : PatternRecognizer
{
    private static readonly IReadOnlyList<Pattern> DefaultPatterns =
    [
        new Pattern(
            "Driver License - Alphanumeric (weak)",
            @"\b([A-Z][0-9]{3,6}|[A-Z][0-9]{5,9}|[A-Z][0-9]{6,8}|[A-Z][0-9]{4,8}|[A-Z][0-9]{9,11}|[A-Z]{1,2}[0-9]{5,6}|H[0-9]{8}|V[0-9]{6}|X[0-9]{8}|A-Z]{2}[0-9]{2,5}|[A-Z]{2}[0-9]{3,7}|[0-9]{2}[A-Z]{3}[0-9]{5,6}|[A-Z][0-9]{13,14}|[A-Z][0-9]{18}|[A-Z][0-9]{6}R|[A-Z][0-9]{9}|[A-Z][0-9]{1,12}|[0-9]{9}[A-Z]|[A-Z]{2}[0-9]{6}[A-Z]|[0-9]{8}[A-Z]{2}|[0-9]{3}[A-Z]{2}[0-9]{4}|[A-Z][0-9][A-Z][0-9][A-Z]|[0-9]{7,8}[A-Z])\b",
            0.3),
        new Pattern(
            "Driver License - Digits (very weak)",
            @"\b([0-9]{6,14}|[0-9]{16})\b",
            0.01),
    ];

    private static readonly IReadOnlyList<string> DefaultContext =
        ["driver", "license", "permit", "lic", "identification", "dls", "cdls", "lic#", "driving"];

    /// <summary>Initializes a new instance of the <see cref="UsDriverLicenseRecognizer"/> class.</summary>
    public UsDriverLicenseRecognizer(string supportedEntity = "US_DRIVER_LICENSE", string supportedLanguage = "en")
        : base(supportedEntity, patterns: DefaultPatterns, context: DefaultContext, supportedLanguage: supportedLanguage, countryCode: "us")
    {
    }
}
