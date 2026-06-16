using AgentGuard.Pii.Analyzer;

namespace AgentGuard.Pii.Recognizers.Generic;

/// <summary>
/// Recognizes common credit card numbers using a regex plus the Luhn checksum.
/// </summary>
public sealed class CreditCardRecognizer : PatternRecognizer
{
    private static readonly IReadOnlyList<Pattern> DefaultPatterns =
    [
        new Pattern(
            "All Credit Cards (weak)",
            @"\b(?!1\d{12}(?!\d))((4\d{3})|(5[0-5]\d{2})|(6\d{3})|(1\d{3})|(3\d{3}))[- ]?(\d{3,4})[- ]?(\d{3,4})[- ]?(\d{3,5})\b",
            0.3),
    ];

    private static readonly IReadOnlyList<string> DefaultContext =
        ["credit", "card", "visa", "mastercard", "cc ", "amex", "discover", "jcb", "diners", "maestro", "instapayment"];

    private static readonly IReadOnlyList<(string, string)> ReplacementPairs = [("-", ""), (" ", "")];

    /// <summary>Initializes a new instance of the <see cref="CreditCardRecognizer"/> class.</summary>
    public CreditCardRecognizer(string supportedEntity = "CREDIT_CARD", string supportedLanguage = "en")
        : base(supportedEntity, patterns: DefaultPatterns, context: DefaultContext, supportedLanguage: supportedLanguage)
    {
    }

    /// <inheritdoc />
    public override bool? ValidateResult(string patternText)
    {
        var sanitized = SanitizeValue(patternText, ReplacementPairs);
        return LuhnChecksum(sanitized);
    }

    private static bool LuhnChecksum(string value)
    {
        var digits = new int[value.Length];
        for (var i = 0; i < value.Length; i++)
        {
            if (!char.IsDigit(value[i]))
            {
                return false;
            }

            digits[i] = value[i] - '0';
        }

        var checksum = 0;
        // odd_digits = digits[-1::-2] (from the end, every other), even_digits = digits[-2::-2]
        for (var i = digits.Length - 1; i >= 0; i -= 2)
        {
            checksum += digits[i];
        }

        for (var i = digits.Length - 2; i >= 0; i -= 2)
        {
            var doubled = digits[i] * 2;
            checksum += doubled / 10 + doubled % 10;
        }

        return checksum % 10 == 0;
    }
}
