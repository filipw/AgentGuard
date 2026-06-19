using AgentGuard.Pii.Analyzer;

namespace AgentGuard.Pii.Recognizers.Spain;

/// <summary>
/// Recognizes the Spanish passport number (3 letters followed by 6 digits) using regex. The pattern is
/// very weak; context words are needed to surface a match above the score threshold.
/// </summary>
public sealed class EsPassportRecognizer : PatternRecognizer
{
    private static readonly IReadOnlyList<Pattern> DefaultPatterns =
    [
        new Pattern("ES_PASSPORT", @"\b[A-Z]{3}[0-9]{6}\b", 0.05),
    ];

    private static readonly IReadOnlyList<string> DefaultContext =
        ["pasaporte", "passport", "número de pasaporte", "passport number"];

    /// <summary>Initializes a new instance of the <see cref="EsPassportRecognizer"/> class.</summary>
    public EsPassportRecognizer(string supportedEntity = "ES_PASSPORT", string supportedLanguage = "en")
        : base(supportedEntity, patterns: DefaultPatterns, context: DefaultContext, supportedLanguage: supportedLanguage, countryCode: "es")
    {
    }
}
