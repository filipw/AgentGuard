using AgentGuard.Pii.Analyzer;

namespace AgentGuard.Pii.Recognizers.Germany;

/// <summary>
/// Recognizes the German Steuernummer (Finanzamt tax number) using regex over the unified ELSTER and
/// state-specific slash formats.
/// </summary>
public sealed class DeTaxNumberRecognizer : PatternRecognizer
{
    private static readonly IReadOnlyList<Pattern> DefaultPatterns =
    [
        new Pattern("Steuernummer ELSTER (bundeseinheitlich, 13-stellig)", @"\b(0[1-9]|1[0-6])\d{11}\b", 0.5),
        new Pattern("Steuernummer mit Schrägstrich (3/3/5)", @"(?<!\w)\d{3}/\d{3}/\d{5}(?!\w)", 0.4),
        new Pattern("Steuernummer mit Schrägstrich (allgemein)", @"(?<!\w)\d{2,3}/\d{3,4}/\d{4,5}(?!\w)", 0.2),
    ];

    private static readonly IReadOnlyList<string> DefaultContext =
    [
        "steuernummer", "steuer-nr", "steuer nr", "st.-nr", "st-nr", "finanzamt", "umsatzsteuer",
        "einkommensteuer", "körperschaftsteuer", "gewerbesteuer", "steuerveranlagung", "steuerbescheid",
    ];

    /// <summary>Initializes a new instance of the <see cref="DeTaxNumberRecognizer"/> class.</summary>
    public DeTaxNumberRecognizer(string supportedEntity = "DE_TAX_NUMBER", string supportedLanguage = "en")
        : base(supportedEntity, patterns: DefaultPatterns, context: DefaultContext, supportedLanguage: supportedLanguage, countryCode: "de")
    {
    }
}
