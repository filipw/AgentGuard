using AgentGuard.Pii.Analyzer;

namespace AgentGuard.Pii.Recognizers.Italy;

/// <summary>
/// Recognizes the Italian identity card number (paper-based and electronic CIE formats) using regex.
/// The patterns are very weak; context words are needed to surface a match above the score threshold.
/// </summary>
public sealed class ItIdentityCardRecognizer : PatternRecognizer
{
    private static readonly IReadOnlyList<Pattern> DefaultPatterns =
    [
        new Pattern("Paper-based Identity Card (very weak)", @"(?i)\b[A-Z]{2}\s?\d{7}\b", 0.01),
        new Pattern("Electronic Identity Card (CIE) 2.0 (very weak)", @"(?i)\b\d{7}[A-Z]{2}\b", 0.01),
        new Pattern("Electronic Identity Card (CIE) 3.0 (very weak)", @"(?i)\b[A-Z]{2}\d{5}[A-Z]{2}\b", 0.01),
    ];

    private static readonly IReadOnlyList<string> DefaultContext =
        ["carta", "identità", "elettronica", "cie", "documento", "riconoscimento", "espatrio"];

    /// <summary>Initializes a new instance of the <see cref="ItIdentityCardRecognizer"/> class.</summary>
    public ItIdentityCardRecognizer(string supportedEntity = "IT_IDENTITY_CARD", string supportedLanguage = "en")
        : base(supportedEntity, patterns: DefaultPatterns, context: DefaultContext, supportedLanguage: supportedLanguage, countryCode: "it")
    {
    }
}
