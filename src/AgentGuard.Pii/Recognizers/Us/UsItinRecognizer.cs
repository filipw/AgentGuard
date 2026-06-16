using AgentGuard.Pii.Analyzer;

namespace AgentGuard.Pii.Recognizers.Us;

/// <summary>
/// Recognizes US Individual Taxpayer Identification Numbers using regex.
/// </summary>
public sealed class UsItinRecognizer : PatternRecognizer
{
    private static readonly IReadOnlyList<Pattern> DefaultPatterns =
    [
        new Pattern(
            "Itin (very weak)",
            @"\b9\d{2}[- ](5\d|6[0-5]|7\d|8[0-8]|9([0-2]|[4-9]))\d{4}\b|\b9\d{2}(5\d|6[0-5]|7\d|8[0-8]|9([0-2]|[4-9]))[- ]\d{4}\b",
            0.05),
        new Pattern(
            "Itin (weak)",
            @"\b9\d{2}(5\d|6[0-5]|7\d|8[0-8]|9([0-2]|[4-9]))\d{4}\b",
            0.3),
        new Pattern(
            "Itin (medium)",
            @"\b9\d{2}[- ](5\d|6[0-5]|7\d|8[0-8]|9([0-2]|[4-9]))[- ]\d{4}\b",
            0.5),
    ];

    private static readonly IReadOnlyList<string> DefaultContext =
        ["individual", "taxpayer", "itin", "tax", "payer", "taxid", "tin"];

    /// <summary>Initializes a new instance of the <see cref="UsItinRecognizer"/> class.</summary>
    public UsItinRecognizer(string supportedEntity = "US_ITIN", string supportedLanguage = "en")
        : base(supportedEntity, patterns: DefaultPatterns, context: DefaultContext, supportedLanguage: supportedLanguage)
    {
    }
}
