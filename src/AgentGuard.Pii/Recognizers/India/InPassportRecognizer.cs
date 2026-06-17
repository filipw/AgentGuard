using AgentGuard.Pii.Analyzer;

namespace AgentGuard.Pii.Recognizers.India;

/// <summary>
/// Recognizes the Indian passport number (eight-character alphanumeric) using regex. The base score is
/// low; context words are needed to surface a match above the score threshold.
/// </summary>
public sealed class InPassportRecognizer : PatternRecognizer
{
    private static readonly IReadOnlyList<Pattern> DefaultPatterns =
    [
        new Pattern("PASSPORT", @"\b[A-Z][1-9]\d\s?\d{4}[1-9]\b", 0.1),
    ];

    private static readonly IReadOnlyList<string> DefaultContext = ["passport", "indian passport", "passport number"];

    /// <summary>Initializes a new instance of the <see cref="InPassportRecognizer"/> class.</summary>
    public InPassportRecognizer(string supportedEntity = "IN_PASSPORT", string supportedLanguage = "en")
        : base(supportedEntity, patterns: DefaultPatterns, context: DefaultContext, supportedLanguage: supportedLanguage, countryCode: "in")
    {
    }
}
