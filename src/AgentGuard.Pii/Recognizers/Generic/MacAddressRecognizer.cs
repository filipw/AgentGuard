using System.Text.RegularExpressions;
using AgentGuard.Pii.Analyzer;

namespace AgentGuard.Pii.Recognizers.Generic;

/// <summary>
/// Recognizes MAC addresses in colon/hyphen and Cisco dot notations.
/// </summary>
public sealed partial class MacAddressRecognizer : PatternRecognizer
{
    private static readonly IReadOnlyList<Pattern> DefaultPatterns =
    [
        new Pattern("MAC_COLON_OR_HYPHEN", @"\b[0-9A-Fa-f]{2}([:-])(?:[0-9A-Fa-f]{2}\1){4}[0-9A-Fa-f]{2}\b", 0.6),
        new Pattern("MAC_CISCO_DOT", @"\b[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\b", 0.6),
    ];

    private static readonly IReadOnlyList<string> DefaultContext =
        ["mac", "mac address", "hardware address", "physical address", "ethernet"];

    /// <summary>Initializes a new instance of the <see cref="MacAddressRecognizer"/> class.</summary>
    public MacAddressRecognizer(string supportedEntity = "MAC_ADDRESS", string supportedLanguage = "en")
        : base(supportedEntity, patterns: DefaultPatterns, context: DefaultContext, supportedLanguage: supportedLanguage)
    {
    }

    /// <inheritdoc />
    public override bool? InvalidateResult(string patternText)
    {
        var cleaned = SeparatorRegex().Replace(patternText, "");
        if (!HexRegex().IsMatch(cleaned))
        {
            return true;
        }

        var upper = cleaned.ToUpperInvariant();
        return upper is "FFFFFFFFFFFF" or "000000000000";
    }

    [GeneratedRegex(@"[:\-.]")]
    private static partial Regex SeparatorRegex();

    [GeneratedRegex("^[0-9A-Fa-f]{12}$")]
    private static partial Regex HexRegex();
}
