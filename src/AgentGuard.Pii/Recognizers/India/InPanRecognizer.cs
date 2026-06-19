using AgentGuard.Pii.Analyzer;

namespace AgentGuard.Pii.Recognizers.India;

/// <summary>
/// Recognizes the Indian Permanent Account Number (PAN), a ten-character alphanumeric code, using regex.
/// </summary>
public sealed class InPanRecognizer : PatternRecognizer
{
    private static readonly IReadOnlyList<Pattern> DefaultPatterns =
    [
        new Pattern("PAN (High)", @"\b([A-Za-z]{3}[AaBbCcFfGgHhJjLlPpTt]{1}[A-Za-z]{1}[0-9]{4}[A-Za-z]{1})\b", 0.5),
        new Pattern("PAN (Medium)", @"\b([A-Za-z]{5}[0-9]{4}[A-Za-z]{1})\b", 0.1),
        new Pattern("PAN (Low)", @"\b((?=.*?[a-zA-Z])(?=.*?[0-9]{4})[\w@#$%^?~-]{10})\b", 0.01),
    ];

    private static readonly IReadOnlyList<string> DefaultContext = ["permanent account number", "pan"];

    /// <summary>Initializes a new instance of the <see cref="InPanRecognizer"/> class.</summary>
    public InPanRecognizer(string supportedEntity = "IN_PAN", string supportedLanguage = "en")
        : base(supportedEntity, patterns: DefaultPatterns, context: DefaultContext, supportedLanguage: supportedLanguage, countryCode: "in")
    {
    }
}
