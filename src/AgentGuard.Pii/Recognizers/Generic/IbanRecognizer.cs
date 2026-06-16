using System.Numerics;
using AgentGuard.Pii.Analyzer;

namespace AgentGuard.Pii.Recognizers.Generic;

/// <summary>
/// Recognizes IBAN codes using regex plus the ISO 7064 mod-97 checksum.
/// </summary>
public sealed class IbanRecognizer : PatternRecognizer
{
    private static readonly IReadOnlyList<Pattern> DefaultPatterns =
    [
        new Pattern(
            "IBAN Generic",
            @"\b[A-Z]{2}[0-9]{2}(?:[ -]?[A-Z0-9]{4}){2,7}(?:[ -]?[A-Z0-9]{1,3})?\b",
            0.5),
    ];

    private static readonly IReadOnlyList<string> DefaultContext = ["iban", "bank", "transaction"];

    private static readonly IReadOnlyList<(string, string)> ReplacementPairs = [("-", ""), (" ", "")];

    /// <summary>Initializes a new instance of the <see cref="IbanRecognizer"/> class.</summary>
    public IbanRecognizer(string supportedEntity = "IBAN_CODE", string supportedLanguage = "en")
        : base(supportedEntity, patterns: DefaultPatterns, context: DefaultContext, supportedLanguage: supportedLanguage)
    {
    }

    /// <inheritdoc />
    public override bool? ValidateResult(string patternText)
    {
        var iban = SanitizeValue(patternText, ReplacementPairs).ToUpperInvariant();
        if (iban.Length < 4)
        {
            return false;
        }

        return IsValidChecksum(iban);
    }

    private static bool IsValidChecksum(string iban)
    {
        // move the first four characters to the end, then map letters to numbers (A=10 .. Z=35)
        var rearranged = iban[4..] + iban[..4];
        var numeric = new System.Text.StringBuilder(rearranged.Length * 2);
        foreach (var c in rearranged)
        {
            if (c >= '0' && c <= '9')
            {
                numeric.Append(c);
            }
            else if (c >= 'A' && c <= 'Z')
            {
                numeric.Append((c - 'A' + 10).ToString(System.Globalization.CultureInfo.InvariantCulture));
            }
            else
            {
                return false;
            }
        }

        return BigInteger.TryParse(numeric.ToString(), out var value) && value % 97 == 1;
    }
}
