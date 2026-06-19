using AgentGuard.Pii.Analyzer;

namespace AgentGuard.Pii.Recognizers.India;

/// <summary>
/// Recognizes the Indian Voter ID (EPIC), a ten-character alphanumeric code, using regex.
/// </summary>
public sealed class InVoterRecognizer : PatternRecognizer
{
    private static readonly IReadOnlyList<Pattern> DefaultPatterns =
    [
        new Pattern("VOTER", @"\b([A-Za-z]{1}[ABCDGHJKMNPRSYabcdghjkmnprsy]{1}[A-Za-z]{1}([0-9]){7})\b", 0.4),
        new Pattern("VOTER", @"\b([A-Za-z]){3}([0-9]){7}\b", 0.3),
    ];

    private static readonly IReadOnlyList<string> DefaultContext = ["voter", "epic", "elector photo identity card"];

    /// <summary>Initializes a new instance of the <see cref="InVoterRecognizer"/> class.</summary>
    public InVoterRecognizer(string supportedEntity = "IN_VOTER", string supportedLanguage = "en")
        : base(supportedEntity, patterns: DefaultPatterns, context: DefaultContext, supportedLanguage: supportedLanguage, countryCode: "in")
    {
    }
}
