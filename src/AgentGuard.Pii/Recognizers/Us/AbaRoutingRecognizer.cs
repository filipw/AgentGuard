using AgentGuard.Pii.Analyzer;

namespace AgentGuard.Pii.Recognizers.Us;

/// <summary>
/// Recognizes American Bankers Association (ABA) routing transit numbers using regex plus a
/// weighted mod-10 checksum.
/// </summary>
public sealed class AbaRoutingRecognizer : PatternRecognizer
{
    private static readonly IReadOnlyList<Pattern> DefaultPatterns =
    [
        new Pattern("ABA routing number (weak)", @"\b[0123678]\d{8}\b", 0.05),
        new Pattern("ABA routing number", @"\b[0123678]\d{3}-\d{4}-\d\b", 0.3),
    ];

    private static readonly IReadOnlyList<string> DefaultContext =
        ["aba", "routing", "abarouting", "association", "bankrouting"];

    private static readonly IReadOnlyList<(string, string)> ReplacementPairs = [("-", "")];

    private static readonly int[] Weights = [3, 7, 1, 3, 7, 1, 3, 7, 1];

    /// <summary>Initializes a new instance of the <see cref="AbaRoutingRecognizer"/> class.</summary>
    public AbaRoutingRecognizer(string supportedEntity = "ABA_ROUTING_NUMBER", string supportedLanguage = "en")
        : base(supportedEntity, patterns: DefaultPatterns, context: DefaultContext, supportedLanguage: supportedLanguage, countryCode: "us")
    {
    }

    /// <inheritdoc />
    public override bool? ValidateResult(string patternText)
    {
        var value = SanitizeValue(patternText, ReplacementPairs);
        if (value.Length < 9 || !value.All(char.IsDigit))
        {
            return false;
        }

        var sum = 0;
        for (var i = 0; i < 9; i++)
        {
            sum += (value[i] - '0') * Weights[i];
        }

        return sum % 10 == 0;
    }
}
