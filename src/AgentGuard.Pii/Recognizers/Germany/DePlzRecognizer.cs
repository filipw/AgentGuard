using AgentGuard.Pii.Analyzer;

namespace AgentGuard.Pii.Recognizers.Germany;

/// <summary>
/// Recognizes German postal codes (Postleitzahl, PLZ). The base score is very low because a bare
/// 5-digit number is highly ambiguous; context words are needed to surface a match.
/// </summary>
public sealed class DePlzRecognizer : PatternRecognizer
{
    private static readonly IReadOnlyList<Pattern> DefaultPatterns =
    [
        new Pattern(
            "Postleitzahl (5 digits, context required)",
            @"\b(?!01000\b|99999\b)(0[1-9]\d{3}|[1-9]\d{4})\b",
            0.05),
    ];

    private static readonly IReadOnlyList<string> DefaultContext =
    [
        "plz", "postleitzahl", "postanschrift", "adresse", "wohnort", "ort", "wohnanschrift",
        "lieferadresse", "rechnungsadresse", "straße", "strasse", "hausnummer", "postfach",
        "bundesland", "gemeinde", "stadt", "dorf",
    ];

    /// <summary>Initializes a new instance of the <see cref="DePlzRecognizer"/> class.</summary>
    public DePlzRecognizer(string supportedEntity = "DE_PLZ", string supportedLanguage = "en")
        : base(supportedEntity, patterns: DefaultPatterns, context: DefaultContext, supportedLanguage: supportedLanguage, countryCode: "de")
    {
    }
}
