using AgentGuard.Pii.Analyzer;

namespace AgentGuard.Pii.Recognizers.Spain;

/// <summary>
/// Recognizes the Spanish NIF / DNI number using regex plus the mod-23 control letter.
/// </summary>
public sealed class EsNifRecognizer : PatternRecognizer
{
    /// <summary>The control-letter lookup table indexed by (number mod 23).</summary>
    internal const string ControlLetters = "TRWAGMYFPDXBNJZSQVHLCKE";

    private static readonly IReadOnlyList<Pattern> DefaultPatterns =
    [
        new Pattern("NIF", @"\b[0-9]?[0-9]{7}[-]?[A-Z]\b", 0.5),
    ];

    private static readonly IReadOnlyList<string> DefaultContext =
        ["documento nacional de identidad", "DNI", "NIF", "identificación"];

    private static readonly IReadOnlyList<(string, string)> ReplacementPairs = [("-", ""), (" ", "")];

    /// <summary>Initializes a new instance of the <see cref="EsNifRecognizer"/> class.</summary>
    public EsNifRecognizer(string supportedEntity = "ES_NIF", string supportedLanguage = "en")
        : base(supportedEntity, patterns: DefaultPatterns, context: DefaultContext, supportedLanguage: supportedLanguage, countryCode: "es")
    {
    }

    /// <inheritdoc />
    public override bool? ValidateResult(string patternText)
    {
        var text = SanitizeValue(patternText, ReplacementPairs);
        if (text.Length < 2 || !char.IsLetter(text[^1]))
        {
            return false;
        }

        var letter = char.ToUpperInvariant(text[^1]);
        var digits = new string(text.Where(char.IsDigit).ToArray());
        if (digits.Length == 0)
        {
            return false;
        }

        var number = long.Parse(digits, System.Globalization.CultureInfo.InvariantCulture);
        return letter == ControlLetters[(int)(number % 23)];
    }
}
