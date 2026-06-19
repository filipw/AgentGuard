using AgentGuard.Pii.Analyzer;

namespace AgentGuard.Pii.Recognizers.Uk;

/// <summary>
/// Recognizes UK postcodes using regex over the position-specific letter rules. The base score is
/// low; context words are needed to surface a match above the score threshold.
/// </summary>
public sealed class UkPostcodeRecognizer : PatternRecognizer
{
    private static readonly IReadOnlyList<Pattern> DefaultPatterns =
    [
        new Pattern(
            "UK Postcode",
            @"\b(GIR\s?0AA|[A-PR-UWYZ][0-9][ABCDEFGHJKPSTUW]?\s?[0-9][ABD-HJLNP-UW-Z]{2}|[A-PR-UWYZ][0-9]{2}\s?[0-9][ABD-HJLNP-UW-Z]{2}|[A-PR-UWYZ][A-HK-Y][0-9][ABEHMNPRVWXY]?\s?[0-9][ABD-HJLNP-UW-Z]{2}|[A-PR-UWYZ][A-HK-Y][0-9]{2}\s?[0-9][ABD-HJLNP-UW-Z]{2})\b",
            0.1),
    ];

    private static readonly IReadOnlyList<string> DefaultContext =
    [
        "postcode", "post code", "postal code", "zip", "address", "delivery", "mailing",
        "shipping", "correspondence",
    ];

    /// <summary>Initializes a new instance of the <see cref="UkPostcodeRecognizer"/> class.</summary>
    public UkPostcodeRecognizer(string supportedEntity = "UK_POSTCODE", string supportedLanguage = "en")
        : base(supportedEntity, patterns: DefaultPatterns, context: DefaultContext, supportedLanguage: supportedLanguage, countryCode: "uk")
    {
    }
}
