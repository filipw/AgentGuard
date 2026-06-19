using System.Text.RegularExpressions;
using AgentGuard.Pii.Analyzer;

namespace AgentGuard.Pii.Recognizers.Germany;

/// <summary>
/// Recognizes the German Umsatzsteuer-Identifikationsnummer ("DE" + 9 digits) using regex plus a
/// heuristic ISO 7064 Mod 11,10 check digit. The check digit is not published, so by default a
/// checksum mismatch abstains (keeps the pattern score) rather than dropping the match; set
/// <c>strictChecksum</c> to drop on mismatch.
/// </summary>
public sealed partial class DeVatIdRecognizer : PatternRecognizer
{
    private static readonly IReadOnlyList<Pattern> DefaultPatterns =
    [
        new Pattern("USt-IdNr. (DE + 9 digits)", @"\bDE\d{9}\b", 0.5),
        new Pattern("USt-IdNr. (with separators)", @"\bDE[\s.\-]?\d{3}[\s.\-]?\d{3}[\s.\-]?\d{3}\b", 0.4),
    ];

    private static readonly IReadOnlyList<string> DefaultContext =
    [
        "umsatzsteuer-identifikationsnummer", "umsatzsteueridentifikationsnummer", "ust-idnr",
        "ust-id", "ustidnr", "umsatzsteuer-id", "mehrwertsteuer", "vat", "vat-id", "vat id",
        "steueridentifikation", "bzst", "bundeszentralamt für steuern", "finanzamt", "invoice", "rechnung",
    ];

    private readonly bool _strictChecksum;

    /// <summary>Initializes a new instance of the <see cref="DeVatIdRecognizer"/> class.</summary>
    /// <param name="strictChecksum">When true, a checksum mismatch drops the match instead of abstaining.</param>
    public DeVatIdRecognizer(string supportedEntity = "DE_VAT_ID", string supportedLanguage = "en", bool strictChecksum = false)
        : base(supportedEntity, patterns: DefaultPatterns, context: DefaultContext, supportedLanguage: supportedLanguage, countryCode: "de")
    {
        _strictChecksum = strictChecksum;
    }

    /// <inheritdoc />
    public override bool? ValidateResult(string patternText)
    {
        var normalized = SeparatorRegex().Replace(patternText.ToUpperInvariant(), "");
        if (normalized.Length != 11 || !normalized.StartsWith("DE", StringComparison.Ordinal))
        {
            return false;
        }

        var digits = normalized[2..];
        if (!digits.All(char.IsDigit))
        {
            return false;
        }

        if (Iso7064Mod1110.ComputeCheckDigit(digits.AsSpan(0, 8)) == digits[8] - '0')
        {
            return true;
        }

        // checksum mismatch: strict mode rejects, default mode abstains to preserve recall
        return _strictChecksum ? false : null;
    }

    [GeneratedRegex(@"[\s.\-]")]
    private static partial Regex SeparatorRegex();
}
