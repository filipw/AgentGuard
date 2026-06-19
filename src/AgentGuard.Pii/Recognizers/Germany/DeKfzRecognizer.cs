using AgentGuard.Pii.Analyzer;

namespace AgentGuard.Pii.Recognizers.Germany;

/// <summary>
/// Recognizes German vehicle registration plates (KFZ-Kennzeichen) using regex over the
/// district-letter / recognition-letter / digit structure.
/// </summary>
public sealed class DeKfzRecognizer : PatternRecognizer
{
    private static readonly IReadOnlyList<Pattern> DefaultPatterns =
    [
        new Pattern("KFZ-Kennzeichen (mit Leerzeichen)", @"(?<![\w-])[A-ZÄÖÜ]{1,3}\s[A-Z]{1,2}\s\d{1,4}[EH]?(?!\w)", 0.3),
        new Pattern("KFZ-Kennzeichen (mit Bindestrich)", @"(?<![\w-])[A-ZÄÖÜ]{1,3}-[A-Z]{1,2}-\d{1,4}[EH]?(?!\w)", 0.3),
        new Pattern("KFZ-Kennzeichen (Bindestrich + Leerzeichen)", @"(?<![\w-])[A-ZÄÖÜ]{1,3}-[A-Z]{1,2}\s\d{1,4}[EH]?(?!\w)", 0.3),
        new Pattern("KFZ-Kennzeichen (ASCII only, mit Leerzeichen)", @"(?<![\w-])[A-Z]{1,3}\s[A-Z]{1,2}\s\d{1,4}[EH]?(?!\w)", 0.2),
        new Pattern("KFZ-Kennzeichen (ASCII only, Bindestrich + Leerzeichen)", @"(?<![\w-])[A-Z]{1,3}-[A-Z]{1,2}\s\d{1,4}[EH]?(?!\w)", 0.2),
    ];

    private static readonly IReadOnlyList<string> DefaultContext =
    [
        "kennzeichen", "kfz-kennzeichen", "kraftfahrzeugkennzeichen", "nummernschild",
        "fahrzeugkennzeichen", "zulassung", "kfz", "fahrzeug", "auto", "pkw", "lkw", "fahrzeugschein",
        "fahrzeugbrief", "zulassungsbescheinigung", "amtliches kennzeichen",
    ];

    /// <summary>Initializes a new instance of the <see cref="DeKfzRecognizer"/> class.</summary>
    public DeKfzRecognizer(string supportedEntity = "DE_KFZ", string supportedLanguage = "en")
        : base(supportedEntity, patterns: DefaultPatterns, context: DefaultContext, supportedLanguage: supportedLanguage, countryCode: "de")
    {
    }
}
