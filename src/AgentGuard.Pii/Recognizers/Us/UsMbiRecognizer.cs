using AgentGuard.Pii.Analyzer;

namespace AgentGuard.Pii.Recognizers.Us;

/// <summary>
/// Recognizes US Medicare Beneficiary Identifiers (MBI) using regex over the CMS position-specific
/// character rules.
/// </summary>
public sealed class UsMbiRecognizer : PatternRecognizer
{
    // valid letters: A-Z excluding S, L, O, I, B, Z
    private const string ValidLetters = "ACDEFGHJKMNPQRTUVWXY";
    private const string ValidAlphanumeric = "0-9ACDEFGHJKMNPQRTUVWXY";

    private const string Num = "[0-9]";
    private const string Alpha = "[" + ValidLetters + "]";
    private const string Alphanum = "[" + ValidAlphanumeric + "]";

    private const string MbiNoDash = Num + Alpha + Alphanum + Num + Alpha + Alphanum + Num + Alpha + Alpha + Num + Num;
    private const string MbiWithDash = Num + Alpha + Alphanum + Num + "-" + Alpha + Alphanum + Num + "-" + Alpha + Alpha + Num + Num;

    private static readonly IReadOnlyList<Pattern> DefaultPatterns =
    [
        new Pattern("MBI (weak)", @"\b" + MbiNoDash + @"\b", 0.3),
        new Pattern("MBI (medium)", @"\b" + MbiWithDash + @"\b", 0.5),
    ];

    private static readonly IReadOnlyList<string> DefaultContext =
        ["medicare", "mbi", "beneficiary", "cms", "medicaid", "hic", "hicn"];

    /// <summary>Initializes a new instance of the <see cref="UsMbiRecognizer"/> class.</summary>
    public UsMbiRecognizer(string supportedEntity = "US_MBI", string supportedLanguage = "en")
        : base(supportedEntity, patterns: DefaultPatterns, context: DefaultContext, supportedLanguage: supportedLanguage, countryCode: "us")
    {
    }
}
