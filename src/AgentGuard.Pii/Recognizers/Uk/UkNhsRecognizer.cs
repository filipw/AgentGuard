using AgentGuard.Pii.Analyzer;

namespace AgentGuard.Pii.Recognizers.Uk;

/// <summary>
/// Recognizes UK NHS numbers using regex plus the mod-11 self-check digit.
/// </summary>
public sealed class UkNhsRecognizer : PatternRecognizer
{
    private static readonly IReadOnlyList<Pattern> DefaultPatterns =
    [
        new Pattern("NHS (medium)", @"\b([0-9]{3})[- ]?([0-9]{3})[- ]?([0-9]{4})\b", 0.5),
    ];

    private static readonly IReadOnlyList<string> DefaultContext =
    [
        "national health service", "nhs", "health services authority", "health authority",
    ];

    private static readonly IReadOnlyList<(string, string)> ReplacementPairs = [("-", ""), (" ", "")];

    /// <summary>Initializes a new instance of the <see cref="UkNhsRecognizer"/> class.</summary>
    public UkNhsRecognizer(string supportedEntity = "UK_NHS", string supportedLanguage = "en")
        : base(supportedEntity, patterns: DefaultPatterns, context: DefaultContext, supportedLanguage: supportedLanguage, countryCode: "uk")
    {
    }

    /// <inheritdoc />
    public override bool? ValidateResult(string patternText)
    {
        var text = SanitizeValue(patternText, ReplacementPairs);
        if (text.Length != 10 || !text.All(char.IsDigit))
        {
            return false;
        }

        // weights 10..1 across all ten digits (the trailing weight-1 digit is the self-check); valid iff sum mod 11 == 0
        var total = 0;
        for (var i = 0; i < 10; i++)
        {
            total += (text[i] - '0') * (10 - i);
        }

        return total % 11 == 0;
    }
}
