using AgentGuard.Pii.Analyzer;

namespace AgentGuard.Pii.Recognizers.Germany;

/// <summary>
/// Recognizes German national ID card numbers (Personalausweisnummern) using regex plus the machine
/// readable travel document check digit (weights 7-3-1, letters mapped A=10..Z=35). Legacy "T + 8
/// digits" numbers predate the check digit and are accepted at pattern confidence.
/// </summary>
public sealed class DeIdCardRecognizer : PatternRecognizer
{
    private static readonly IReadOnlyList<Pattern> DefaultPatterns =
    [
        new Pattern(
            "Personalausweisnummer nPA (charset + check digit)",
            @"\b[CFGHJKLMNPRTVWXYZ][CFGHJKLMNPRTVWXYZ0-9]{7}[0-9]\b",
            0.4),
        new Pattern("Personalausweisnummer alt (T + 8 Ziffern)", @"\bT\d{8}\b", 0.5),
    ];

    private static readonly IReadOnlyList<string> DefaultContext =
    [
        "personalausweis", "ausweis", "personalausweisnummer", "ausweisnummer", "ausweisdokument",
        "dokumentennummer", "seriennummer", "npa", "neuer personalausweis", "personalausweisgesetz",
        "pauwsg", "bundespersonalausweis", "identity card", "national id",
    ];

    /// <summary>Initializes a new instance of the <see cref="DeIdCardRecognizer"/> class.</summary>
    public DeIdCardRecognizer(string supportedEntity = "DE_ID_CARD", string supportedLanguage = "en")
        : base(supportedEntity, patterns: DefaultPatterns, context: DefaultContext, supportedLanguage: supportedLanguage, countryCode: "de")
    {
    }

    /// <inheritdoc />
    public override bool? ValidateResult(string patternText)
    {
        var text = patternText.ToUpperInvariant().Trim();
        if (text.Length != 9)
        {
            return false;
        }

        // legacy "T + 8 digits" format predates the check digit and cannot be structurally validated
        if (text[0] == 'T' && text[1..].All(char.IsDigit))
        {
            return null;
        }

        if (!char.IsDigit(text[^1]))
        {
            return false;
        }

        return IcaoCheckDigit.Validate(text);
    }
}
