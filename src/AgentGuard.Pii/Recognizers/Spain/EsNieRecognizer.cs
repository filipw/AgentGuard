using AgentGuard.Pii.Analyzer;

namespace AgentGuard.Pii.Recognizers.Spain;

/// <summary>
/// Recognizes the Spanish NIE (foreigner identity number) using regex plus the mod-23 control letter,
/// where the leading X/Y/Z is mapped to 0/1/2.
/// </summary>
public sealed class EsNieRecognizer : PatternRecognizer
{
    private static readonly IReadOnlyList<Pattern> DefaultPatterns =
    [
        new Pattern("NIE", @"\b[X-Z]?[0-9]?[0-9]{7}[-]?[A-Z]\b", 0.5),
    ];

    private static readonly IReadOnlyList<string> DefaultContext =
        ["número de identificación de extranjero", "NIE"];

    private static readonly IReadOnlyList<(string, string)> ReplacementPairs = [("-", ""), (" ", "")];

    /// <summary>Initializes a new instance of the <see cref="EsNieRecognizer"/> class.</summary>
    public EsNieRecognizer(string supportedEntity = "ES_NIE", string supportedLanguage = "en")
        : base(supportedEntity, patterns: DefaultPatterns, context: DefaultContext, supportedLanguage: supportedLanguage, countryCode: "es")
    {
    }

    /// <inheritdoc />
    public override bool? ValidateResult(string patternText)
    {
        var text = SanitizeValue(patternText, ReplacementPairs).ToUpperInvariant();
        if (text.Length is < 8 or > 9)
        {
            return false;
        }

        var first = text[0];
        if (first is not ('X' or 'Y' or 'Z') || !char.IsLetter(text[^1]))
        {
            return false;
        }

        var body = text[1..^1];
        if (!body.All(char.IsDigit))
        {
            return false;
        }

        // map the leading X/Y/Z to 0/1/2 and prepend it to the numeric body
        var prefixDigit = "XYZ".IndexOf(first);
        var number = long.Parse(prefixDigit + body, System.Globalization.CultureInfo.InvariantCulture);
        return text[^1] == EsNifRecognizer.ControlLetters[(int)(number % 23)];
    }
}
