using AgentGuard.Pii.Analyzer;

namespace AgentGuard.Pii.Recognizers.India;

/// <summary>
/// Recognizes the Indian Goods and Services Tax Identification Number (GSTIN), a 15-character code,
/// using regex plus structural validation (state code, embedded PAN, fixed 'Z' marker).
/// </summary>
public sealed class InGstinRecognizer : PatternRecognizer
{
    private static readonly IReadOnlyList<Pattern> DefaultPatterns =
    [
        new Pattern("GSTIN (High)", @"\b((?:0[1-9]|[1-3][0-7])[A-Za-z0-9]{10}[A-Za-z0-9]{1}Z[A-Za-z0-9]{1})\b", 0.8),
        new Pattern("GSTIN (Medium)", @"\b((?:0[1-9]|[1-3][0-7])[A-Za-z0-9]{11}Z[A-Za-z0-9]{1})\b", 0.4),
        new Pattern("GSTIN (Low)", @"\b([0-9]{2}[A-Za-z0-9]{11}Z[A-Za-z0-9]{1})\b", 0.1),
    ];

    private static readonly IReadOnlyList<string> DefaultContext =
    [
        "gstin", "gst", "goods and services tax", "tax identification", "gst number", "gst registration",
    ];

    private static readonly IReadOnlyList<(string, string)> ReplacementPairs = [("-", ""), (" ", "")];

    /// <summary>Initializes a new instance of the <see cref="InGstinRecognizer"/> class.</summary>
    public InGstinRecognizer(string supportedEntity = "IN_GSTIN", string supportedLanguage = "en")
        : base(supportedEntity, patterns: DefaultPatterns, context: DefaultContext, supportedLanguage: supportedLanguage, countryCode: "in")
    {
    }

    /// <inheritdoc />
    public override bool? ValidateResult(string patternText)
    {
        var gstin = SanitizeValue(patternText, ReplacementPairs).ToUpperInvariant();
        if (gstin.Length != 15)
        {
            return false;
        }

        // state code 01-37
        if (!char.IsDigit(gstin[0]) || !char.IsDigit(gstin[1]))
        {
            return false;
        }

        var stateCode = int.Parse(gstin[..2], System.Globalization.CultureInfo.InvariantCulture);
        if (stateCode is < 1 or > 37)
        {
            return false;
        }

        // embedded PAN (chars 2-12): at least 3 letters in the first 5, then 4 digits, then a letter
        var pan = gstin[2..12];
        var letterCount = pan[..5].Count(char.IsLetter);
        if (letterCount < 3 || !pan[5..9].All(char.IsDigit) || !char.IsLetter(pan[9]))
        {
            return false;
        }

        // registration char (12) alphanumeric, fixed 'Z' (13), checksum char (14) alphanumeric
        return char.IsLetterOrDigit(gstin[12]) && gstin[13] == 'Z' && char.IsLetterOrDigit(gstin[14]);
    }
}
