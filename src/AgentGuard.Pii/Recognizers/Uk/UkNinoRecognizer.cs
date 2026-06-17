using AgentGuard.Pii.Analyzer;

namespace AgentGuard.Pii.Recognizers.Uk;

/// <summary>
/// Recognizes UK National Insurance Numbers (NINO) using regex over the valid prefix-letter rules.
/// </summary>
public sealed class UkNinoRecognizer : PatternRecognizer
{
    private static readonly IReadOnlyList<Pattern> DefaultPatterns =
    [
        new Pattern(
            "NINO (medium)",
            @"\b(?!bg|gb|nk|kn|nt|tn|zz|BG|GB|NK|KN|NT|TN|ZZ) ?([a-ceghj-pr-tw-zA-CEGHJ-PR-TW-Z]{1}[a-ceghj-npr-tw-zA-CEGHJ-NPR-TW-Z]{1}) ?([0-9]{2}) ?([0-9]{2}) ?([0-9]{2}) ?([a-dA-D{1}])\b",
            0.5),
    ];

    private static readonly IReadOnlyList<string> DefaultContext = ["national insurance", "ni number", "nino"];

    /// <summary>Initializes a new instance of the <see cref="UkNinoRecognizer"/> class.</summary>
    public UkNinoRecognizer(string supportedEntity = "UK_NINO", string supportedLanguage = "en")
        : base(supportedEntity, patterns: DefaultPatterns, context: DefaultContext, supportedLanguage: supportedLanguage, countryCode: "uk")
    {
    }
}
