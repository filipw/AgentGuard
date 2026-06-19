using AgentGuard.Pii.Analyzer;

namespace AgentGuard.Pii.Recognizers.Us;

/// <summary>
/// Recognizes US Social Security Numbers using regex plus pruning of impossible values.
/// </summary>
public sealed class UsSsnRecognizer : PatternRecognizer
{
    private static readonly IReadOnlyList<Pattern> DefaultPatterns =
    [
        new Pattern("SSN1 (very weak)", @"\b([0-9]{5})-([0-9]{4})\b", 0.05),
        new Pattern("SSN2 (very weak)", @"\b([0-9]{3})-([0-9]{6})\b", 0.05),
        new Pattern("SSN3 (very weak)", @"\b(([0-9]{3})-([0-9]{2})-([0-9]{4}))\b", 0.05),
        new Pattern("SSN4 (very weak)", @"\b[0-9]{9}\b", 0.05),
        new Pattern("SSN5 (medium)", @"\b([0-9]{3})[- .]([0-9]{2})[- .]([0-9]{4})\b", 0.5),
    ];

    private static readonly IReadOnlyList<string> DefaultContext = ["social", "security", "ssn", "ssns", "ssid"];

    private static readonly string[] BlacklistedSamples = ["000", "666", "123456789", "98765432", "078051120"];

    /// <summary>Initializes a new instance of the <see cref="UsSsnRecognizer"/> class.</summary>
    public UsSsnRecognizer(string supportedEntity = "US_SSN", string supportedLanguage = "en")
        : base(supportedEntity, patterns: DefaultPatterns, context: DefaultContext, supportedLanguage: supportedLanguage)
    {
    }

    /// <inheritdoc />
    public override bool? InvalidateResult(string patternText)
    {
        // delimiters must be consistent
        var delimiters = patternText.Where(c => c is '.' or '-' or ' ').Distinct().Count();
        if (delimiters > 1)
        {
            return true;
        }

        var onlyDigits = new string(patternText.Where(char.IsDigit).ToArray());
        if (onlyDigits.Length == 0)
        {
            return true;
        }

        // cannot be all the same digit
        if (onlyDigits.All(c => c == onlyDigits[0]))
        {
            return true;
        }

        // group cannot be all zeros
        if (onlyDigits.Length >= 9 &&
            (onlyDigits[3..5] == "00" || onlyDigits[5..] == "0000"))
        {
            return true;
        }

        foreach (var sample in BlacklistedSamples)
        {
            if (onlyDigits.StartsWith(sample, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }
}
