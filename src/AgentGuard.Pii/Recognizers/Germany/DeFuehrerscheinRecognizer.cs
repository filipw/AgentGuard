using AgentGuard.Pii.Analyzer;

namespace AgentGuard.Pii.Recognizers.Germany;

/// <summary>
/// Recognizes German driving licence document numbers (post-2013 EU format, 11 characters) using
/// regex. No checksum is available because the derivation algorithm is not published.
/// </summary>
public sealed class DeFuehrerscheinRecognizer : PatternRecognizer
{
    private static readonly IReadOnlyList<Pattern> DefaultPatterns =
    [
        new Pattern("Führerscheinnummer (Post-2013 EU-Format, 11 Zeichen)", @"\b[A-Z]{2}\d{8}[A-Z0-9]\b", 0.35),
    ];

    private static readonly IReadOnlyList<string> DefaultContext =
    [
        "führerscheinnummer", "führerschein", "fahrerlaubnis", "fahrerlaubnisnummer",
        "fahrerlaubnisklasse", "führerscheininhaber", "fev", "kba", "kraftfahrt-bundesamt",
        "driving licence", "driving license", "driver's license", "licence number", "license number",
        "dokument nr", "dokument-nr", "feld 5",
    ];

    /// <summary>Initializes a new instance of the <see cref="DeFuehrerscheinRecognizer"/> class.</summary>
    public DeFuehrerscheinRecognizer(string supportedEntity = "DE_FUEHRERSCHEIN", string supportedLanguage = "en")
        : base(supportedEntity, patterns: DefaultPatterns, context: DefaultContext, supportedLanguage: supportedLanguage, countryCode: "de")
    {
    }
}
