using AgentGuard.Pii.Analyzer;

namespace AgentGuard.Pii.Recognizers.Italy;

/// <summary>
/// Recognizes the Italian passport number (2 letters followed by 7 digits) using regex. The pattern
/// is very weak; context words are needed to surface a match above the score threshold.
/// </summary>
public sealed class ItPassportRecognizer : PatternRecognizer
{
    private static readonly IReadOnlyList<Pattern> DefaultPatterns =
    [
        new Pattern("Passport (very weak)", @"(?i)\b[A-Z]{2}\d{7}\b", 0.01),
    ];

    private static readonly IReadOnlyList<string> DefaultContext =
        ["passaporto", "elettronico", "italiano", "viaggio", "viaggiare", "estero", "documento", "dogana"];

    /// <summary>Initializes a new instance of the <see cref="ItPassportRecognizer"/> class.</summary>
    public ItPassportRecognizer(string supportedEntity = "IT_PASSPORT", string supportedLanguage = "en")
        : base(supportedEntity, patterns: DefaultPatterns, context: DefaultContext, supportedLanguage: supportedLanguage, countryCode: "it")
    {
    }
}
