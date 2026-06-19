using AgentGuard.Pii.Analyzer;

namespace AgentGuard.Pii.Recognizers.Uk;

/// <summary>
/// Recognizes UK passport numbers (2-letter prefix followed by 7 digits) using regex. The base score
/// is low; context words are needed to surface a match above the score threshold.
/// </summary>
public sealed class UkPassportRecognizer : PatternRecognizer
{
    private static readonly IReadOnlyList<Pattern> DefaultPatterns =
    [
        new Pattern("UK Passport (weak)", @"\b[A-Z]{2}\d{7}\b", 0.1),
    ];

    private static readonly IReadOnlyList<string> DefaultContext =
    [
        "passport", "passport number", "travel document", "uk passport", "british passport",
        "her majesty", "his majesty", "hm passport", "hmpo",
    ];

    /// <summary>Initializes a new instance of the <see cref="UkPassportRecognizer"/> class.</summary>
    public UkPassportRecognizer(string supportedEntity = "UK_PASSPORT", string supportedLanguage = "en")
        : base(supportedEntity, patterns: DefaultPatterns, context: DefaultContext, supportedLanguage: supportedLanguage, countryCode: "uk")
    {
    }
}
