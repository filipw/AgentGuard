using AgentGuard.Pii.Analyzer;

namespace AgentGuard.Pii.Recognizers.Germany;

/// <summary>
/// Recognizes German passport numbers (Reisepassnummern) using regex over the restricted charset plus
/// the machine readable travel document check digit.
/// </summary>
public sealed class DePassportRecognizer : PatternRecognizer
{
    private static readonly IReadOnlyList<Pattern> DefaultPatterns =
    [
        new Pattern(
            "Reisepassnummer (strict charset)",
            @"\b[CFGHJKLMNPRTVWXYZ][CFGHJKLMNPRTVWXYZ0-9]{7}[0-9]\b",
            0.4),
    ];

    private static readonly IReadOnlyList<string> DefaultContext =
    [
        "reisepass", "pass", "passnummer", "reisepassnummer", "passport", "passport number",
        "pass-nr", "dokumentennummer", "bundesrepublik deutschland", "ausweisdokument", "mrz",
    ];

    // visually ambiguous letters excluded from travel-document serial numbers
    private static readonly char[] Forbidden = ['A', 'B', 'D', 'E', 'I', 'O', 'Q', 'S', 'U'];

    /// <summary>Initializes a new instance of the <see cref="DePassportRecognizer"/> class.</summary>
    public DePassportRecognizer(string supportedEntity = "DE_PASSPORT", string supportedLanguage = "en")
        : base(supportedEntity, patterns: DefaultPatterns, context: DefaultContext, supportedLanguage: supportedLanguage, countryCode: "de")
    {
    }

    /// <inheritdoc />
    public override bool? ValidateResult(string patternText)
    {
        var text = patternText.ToUpperInvariant().Trim();
        if (text.Length != 9 || !char.IsDigit(text[^1]))
        {
            return false;
        }

        for (var i = 0; i < text.Length - 1; i++)
        {
            if (Array.IndexOf(Forbidden, text[i]) >= 0)
            {
                return false;
            }
        }

        return IcaoCheckDigit.Validate(text);
    }
}
