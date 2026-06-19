using AgentGuard.Pii.Analyzer;

namespace AgentGuard.Pii.Recognizers.Germany;

/// <summary>
/// Recognizes the German Steueridentifikationsnummer (11-digit personal tax id) using regex plus the
/// ISO 7064 Mod 11,10 check digit and the digit-repetition structural rule.
/// </summary>
public sealed class DeTaxIdRecognizer : PatternRecognizer
{
    private static readonly IReadOnlyList<Pattern> DefaultPatterns =
    [
        new Pattern("Steueridentifikationsnummer (High)", @"\b[1-9]\d{10}\b", 0.5),
    ];

    private static readonly IReadOnlyList<string> DefaultContext =
    [
        "steueridentifikationsnummer", "steuer-id", "steuerid", "steuerliche identifikationsnummer",
        "steuerliche identifikation", "persönliche identifikationsnummer", "steuer identifikation",
        "idnr", "steuer-idnr", "steuernummer", "bzst",
    ];

    /// <summary>Initializes a new instance of the <see cref="DeTaxIdRecognizer"/> class.</summary>
    public DeTaxIdRecognizer(string supportedEntity = "DE_TAX_ID", string supportedLanguage = "en")
        : base(supportedEntity, patterns: DefaultPatterns, context: DefaultContext, supportedLanguage: supportedLanguage, countryCode: "de")
    {
    }

    /// <inheritdoc />
    public override bool? ValidateResult(string patternText)
    {
        if (patternText.Length != 11 || !patternText.All(char.IsDigit) || patternText[0] == '0')
        {
            return false;
        }

        // post-2016 rule: no digit may appear more than three times across the first ten positions
        var counts = new int[10];
        for (var i = 0; i < 10; i++)
        {
            if (++counts[patternText[i] - '0'] > 3)
            {
                return false;
            }
        }

        return Iso7064Mod1110.ComputeCheckDigit(patternText.AsSpan(0, 10)) == patternText[10] - '0';
    }
}
