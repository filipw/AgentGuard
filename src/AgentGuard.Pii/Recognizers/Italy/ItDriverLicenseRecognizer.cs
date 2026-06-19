using AgentGuard.Pii.Analyzer;

namespace AgentGuard.Pii.Recognizers.Italy;

/// <summary>
/// Recognizes the Italian driver license number using regex.
/// </summary>
public sealed class ItDriverLicenseRecognizer : PatternRecognizer
{
    private static readonly IReadOnlyList<Pattern> DefaultPatterns =
    [
        new Pattern("Driver License", @"\b(?i)(([A-Z]{2}\d{7}[A-Z])|(U1[BCDEFGHLJKMNPRSTUWYXZ0-9]{7}[A-Z]))\b", 0.2),
    ];

    private static readonly IReadOnlyList<string> DefaultContext =
        ["patente", "patente di guida", "licenza", "licenza di guida"];

    /// <summary>Initializes a new instance of the <see cref="ItDriverLicenseRecognizer"/> class.</summary>
    public ItDriverLicenseRecognizer(string supportedEntity = "IT_DRIVER_LICENSE", string supportedLanguage = "en")
        : base(supportedEntity, patterns: DefaultPatterns, context: DefaultContext, supportedLanguage: supportedLanguage, countryCode: "it")
    {
    }
}
