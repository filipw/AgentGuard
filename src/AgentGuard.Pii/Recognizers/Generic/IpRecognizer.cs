using System.Net;
using AgentGuard.Pii.Analyzer;

namespace AgentGuard.Pii.Recognizers.Generic;

/// <summary>
/// Recognizes IPv4 and IPv6 addresses (including CIDR suffixes) using regex, validating each match
/// by parsing it as an IP address.
/// </summary>
public sealed class IpRecognizer : PatternRecognizer
{
    private static readonly IReadOnlyList<Pattern> DefaultPatterns =
    [
        new Pattern(
            "IPv4_mapped",
            @"(?<![\w:])::(?:ffff(?::0{1,4})?:)?(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:/(?:12[0-8]|1[01]\d|[1-9]?\d))?\b",
            0.6),
        new Pattern(
            "IPv4_embedded",
            @"(?<![\w:])(?:(?:[0-9A-Fa-f]{1,4}:){1,5}:(?:[0-9A-Fa-f]{1,4}:){0,4}|(?:[0-9A-Fa-f]{1,4}:){6})(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:/(?:12[0-8]|1[01]\d|[1-9]?\d))?\b",
            0.6),
        new Pattern(
            "IPv4",
            @"\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:/(?:[0-2]?\d|3[0-2]))?\b",
            0.6),
        new Pattern(
            "IPv6",
            @"(?<![\w:])(?:(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){1,7}:|:(?::[0-9A-Fa-f]{1,4}){1,7}|(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}|(?:[0-9A-Fa-f]{1,4}:){1,4}(?::[0-9A-Fa-f]{1,4}){1,3}|(?:[0-9A-Fa-f]{1,4}:){1,3}(?::[0-9A-Fa-f]{1,4}){1,4}|(?:[0-9A-Fa-f]{1,4}:){1,2}(?::[0-9A-Fa-f]{1,4}){1,5}|[0-9A-Fa-f]{1,4}:(?::[0-9A-Fa-f]{1,4}){1,6}|:(?::[0-9A-Fa-f]{1,4}){1,6})(?:%[0-9a-zA-Z]+)?(?:/(?:12[0-8]|1[01]\d|[1-9]?\d))?(?![\w:]|\.\d)",
            0.6),
        new Pattern(
            "IPv6_unspecified",
            @"(?<![\w:])::(?:/(?:12[0-8]|1[01]\d|[1-9]?\d))?(?![\w:])",
            0.1),
    ];

    private static readonly IReadOnlyList<string> DefaultContext = ["ip", "ipv4", "ipv6"];

    /// <summary>Initializes a new instance of the <see cref="IpRecognizer"/> class.</summary>
    public IpRecognizer(string supportedEntity = "IP_ADDRESS", string supportedLanguage = "en")
        : base(supportedEntity, patterns: DefaultPatterns, context: DefaultContext, supportedLanguage: supportedLanguage)
    {
    }

    /// <inheritdoc />
    public override bool? InvalidateResult(string patternText)
    {
        // strip an optional CIDR prefix and IPv6 zone id, then validate the address part
        var address = patternText;
        var slash = address.IndexOf('/', StringComparison.Ordinal);
        if (slash >= 0)
        {
            address = address[..slash];
        }

        var percent = address.IndexOf('%', StringComparison.Ordinal);
        if (percent >= 0)
        {
            address = address[..percent];
        }

        return !IPAddress.TryParse(address, out _);
    }
}
