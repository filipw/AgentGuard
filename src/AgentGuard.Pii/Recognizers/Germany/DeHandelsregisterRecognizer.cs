using AgentGuard.Pii.Analyzer;

namespace AgentGuard.Pii.Recognizers.Germany;

/// <summary>
/// Recognizes German commercial register numbers (Handelsregisternummer, HRA/HRB) using regex. The
/// distinctive prefix keeps false positives low even without a checksum.
/// </summary>
public sealed class DeHandelsregisterRecognizer : PatternRecognizer
{
    private static readonly IReadOnlyList<Pattern> DefaultPatterns =
    [
        new Pattern("Handelsregisternummer HRA/HRB", @"\bHR[AB]\s*\d{1,6}\b", 0.5),
    ];

    private static readonly IReadOnlyList<string> DefaultContext =
    [
        "handelsregister", "handelsregisternummer", "amtsgericht", "registergericht", "hra", "hrb",
        "hr-nummer", "registerauszug", "handelsregistereintrag", "firma", "gesellschaft", "gmbh", "ag",
        "ug", "kg", "ohg", "einzelkaufmann", "einzelkauffrau", "handelsregisterblattnummer",
    ];

    /// <summary>Initializes a new instance of the <see cref="DeHandelsregisterRecognizer"/> class.</summary>
    public DeHandelsregisterRecognizer(string supportedEntity = "DE_HANDELSREGISTER", string supportedLanguage = "en")
        : base(supportedEntity, patterns: DefaultPatterns, context: DefaultContext, supportedLanguage: supportedLanguage, countryCode: "de")
    {
    }
}
