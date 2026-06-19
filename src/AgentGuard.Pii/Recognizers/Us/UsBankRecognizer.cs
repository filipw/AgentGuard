using AgentGuard.Pii.Analyzer;

namespace AgentGuard.Pii.Recognizers.Us;

/// <summary>
/// Recognizes US bank account numbers using regex. The pattern is intentionally weak; context words
/// (e.g. "account", "bank") are needed to surface a match above the score threshold.
/// </summary>
public sealed class UsBankRecognizer : PatternRecognizer
{
    private static readonly IReadOnlyList<Pattern> DefaultPatterns =
    [
        new Pattern("Bank Account (weak)", @"\b[0-9]{8,17}\b", 0.05),
    ];

    private static readonly IReadOnlyList<string> DefaultContext =
        ["check", "account", "account#", "acct", "bank", "save", "debit"];

    /// <summary>Initializes a new instance of the <see cref="UsBankRecognizer"/> class.</summary>
    public UsBankRecognizer(string supportedEntity = "US_BANK_NUMBER", string supportedLanguage = "en")
        : base(supportedEntity, patterns: DefaultPatterns, context: DefaultContext, supportedLanguage: supportedLanguage, countryCode: "us")
    {
    }
}
