using AgentGuard.Pii.Analyzer;

namespace AgentGuard.Pii.Recognizers.India;

/// <summary>
/// Recognizes the Indian UIDAI Aadhaar number (12 digits) using regex plus the Verhoeff checksum,
/// rejecting palindromes and numbers not starting with 2-9.
/// </summary>
public sealed class InAadhaarRecognizer : PatternRecognizer
{
    private static readonly IReadOnlyList<Pattern> DefaultPatterns =
    [
        new Pattern("AADHAAR (Very Weak)", @"\b[0-9]{12}\b", 0.01),
        new Pattern("AADHAR (Very Weak)", @"\b[0-9]{4}[- :][0-9]{4}[- :][0-9]{4}\b", 0.01),
    ];

    private static readonly IReadOnlyList<string> DefaultContext = ["aadhaar", "uidai"];

    private static readonly IReadOnlyList<(string, string)> ReplacementPairs = [("-", ""), (" ", ""), (":", "")];

    /// <summary>Initializes a new instance of the <see cref="InAadhaarRecognizer"/> class.</summary>
    public InAadhaarRecognizer(string supportedEntity = "IN_AADHAAR", string supportedLanguage = "en")
        : base(supportedEntity, patterns: DefaultPatterns, context: DefaultContext, supportedLanguage: supportedLanguage, countryCode: "in")
    {
    }

    /// <inheritdoc />
    public override bool? ValidateResult(string patternText)
    {
        var value = SanitizeValue(patternText, ReplacementPairs);
        if (value.Length != 12 || !value.All(char.IsDigit))
        {
            return false;
        }

        if (value[0] < '2')
        {
            return false;
        }

        if (IsPalindrome(value))
        {
            return false;
        }

        return VerhoeffChecksum.IsValid(value);
    }

    private static bool IsPalindrome(string value)
    {
        for (int i = 0, j = value.Length - 1; i < j; i++, j--)
        {
            if (value[i] != value[j])
            {
                return false;
            }
        }

        return true;
    }
}
