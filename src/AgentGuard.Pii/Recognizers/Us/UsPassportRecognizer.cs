using AgentGuard.Pii.Analyzer;

namespace AgentGuard.Pii.Recognizers.Us;

/// <summary>
/// Recognizes US passport numbers using regex. The patterns are weak; context words are needed to
/// surface a match above the score threshold.
/// </summary>
public sealed class UsPassportRecognizer : PatternRecognizer
{
    private static readonly IReadOnlyList<Pattern> DefaultPatterns =
    [
        new Pattern("Passport (very weak)", @"(\b[0-9]{9}\b)", 0.05),
        new Pattern("Passport Next Generation (very weak)", @"(\b[A-Z][0-9]{8}\b)", 0.1),
    ];

    private static readonly IReadOnlyList<string> DefaultContext =
        ["us", "united", "states", "passport", "passport#", "travel", "document"];

    /// <summary>Initializes a new instance of the <see cref="UsPassportRecognizer"/> class.</summary>
    public UsPassportRecognizer(string supportedEntity = "US_PASSPORT", string supportedLanguage = "en")
        : base(supportedEntity, patterns: DefaultPatterns, context: DefaultContext, supportedLanguage: supportedLanguage, countryCode: "us")
    {
    }
}
