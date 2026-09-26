using System.Buffers;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;

namespace AgentGuard.Core.Rules.ToolCall;

/// <summary>
/// Finds URLs and host references in tool call arguments that point at loopback, private,
/// link-local or cloud metadata addresses - the targets of server-side request forgery.
/// </summary>
/// <remarks>
/// Hosts are parsed rather than pattern-matched. A URL's host is read the way a WHATWG URL parser
/// reads it: after any userinfo, before the port, percent-decoded, width- and case-folded, with one
/// trailing dot ignored. An IP literal is then read with <see cref="IPAddress.TryParse(string?, out IPAddress?)"/>,
/// which accepts the legacy IPv4 forms resolvers still honour (<c>2130706433</c>, <c>0x7f000001</c>,
/// <c>0177.0.0.1</c>, <c>127.1</c>), and IPv4 addresses embedded in IPv6 (mapped, compatible, NAT64)
/// are classified as the IPv4 address they carry. Names are never resolved, so a public name that
/// resolves to an internal address is not caught.
/// </remarks>
internal static class SsrfDetector
{
    internal const string Localhost = "Localhost SSRF";
    internal const string InternalNetwork = "Internal network SSRF";
    internal const string CloudMetadata = "Cloud metadata SSRF";
    internal const string InternalHostname = "DNS rebinding via special TLDs";

    // longer than any real host plus userinfo; a longer run is not treated as an authority
    private const int MaxAuthorityLength = 2048;

    private static readonly TimeSpan Timeout = TimeSpan.FromMilliseconds(200);

    // a scheme and the slashes after it. It starts only where a scheme-shaped run starts, and the run
    // is bounded, which keeps the scan linear.
    private static readonly Regex SchemePattern = new(
        @"(?<![A-Za-z0-9+.\-])(?<scheme>[A-Za-z][A-Za-z0-9+.\-]{0,31}):(?<slashes>[/\\]*)",
        RegexOptions.Compiled | RegexOptions.CultureInvariant, Timeout);

    // a protocol-relative authority ("//host") at the start of a token
    private static readonly Regex ProtocolRelativePattern = new(
        @"(?<![^\s""'`(<\[{=,;])[/\\]{2}(?![/\\])",
        RegexOptions.Compiled | RegexOptions.CultureInvariant, Timeout);

    // a host without a scheme - a dotted-quad IPv4 address, a bracketed IPv6 address or a name - at
    // the start of a token, followed by a port, a path or the end of the text. Prose mentions ("the
    // host localhost is down") are left alone, as a URL-less host is only a target when used as one.
    private static readonly Regex BareHostPattern = new(
        @"(?<![\w.\-@/\\:%\[])(?:(?<ip>(?:\d{1,3}\.){3}\d{1,3})|\[(?<ip6>[0-9A-Fa-f:.%]{2,64})\]|(?<name>[A-Za-z0-9\-]{1,63}(?:\.[A-Za-z0-9\-]{1,63}){0,8}))(?:\.(?=[:/\\])|(?=[:/\\]|$))",
        RegexOptions.Compiled | RegexOptions.CultureInvariant, Timeout);

    // well-known metadata endpoints are flagged wherever they appear
    private static readonly Regex MetadataPattern = new(
        @"(?<![\d.])(?:169\.254\.169\.254|169\.254\.170\.2|100\.100\.100\.200|192\.0\.0\.192)(?!\d)|\bmetadata\.google\.internal\b|(?<![0-9A-Fa-f:])fd00:ec2::254(?![0-9A-Fa-f:])",
        RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, Timeout);

    private static readonly SearchValues<char> AuthorityTerminators =
        SearchValues.Create("/\\?#\"'`<>,;)}{|^ \t\r\n\f\v ");

    private static readonly string[] InternalSuffixes = [".internal", ".local", ".corp", ".lan", ".intranet", ".home.arpa"];

    /// <summary>The patterns this detector runs, for warming.</summary>
    internal static IEnumerable<Regex> Patterns => [SchemePattern, ProtocolRelativePattern, BareHostPattern, MetadataPattern];

    /// <summary>
    /// Returns the description of the first SSRF target in <paramref name="text"/>, or <c>null</c>.
    /// </summary>
    internal static string? Find(string text)
    {
        foreach (var match in SchemePattern.MatchesUntilTimeout(text))
        {
            var scheme = match.Groups["scheme"].Value;
            var slashes = match.Groups["slashes"].Length;

            // special schemes take their host after any number of slashes, including none; other
            // schemes only have an authority after "//", and file URLs name a host only between the
            // second and third slash
            if (scheme.Equals("file", StringComparison.OrdinalIgnoreCase) ? slashes != 2 : slashes < 2 && !IsSpecialScheme(scheme))
                continue;

            if (CheckAuthority(text, match.Index + match.Length) is { } description)
                return description;
        }

        foreach (var match in ProtocolRelativePattern.MatchesUntilTimeout(text))
        {
            if (CheckAuthority(text, match.Index + match.Length) is { } description)
                return description;
        }

        foreach (var match in BareHostPattern.MatchesUntilTimeout(text))
        {
            string? description = null;

            if (match.Groups["ip"].Success)
            {
                if (IPAddress.TryParse(match.Groups["ip"].Value, out var address))
                    description = ClassifyAddress(address);
            }
            else if (match.Groups["ip6"].Success)
            {
                description = ClassifyHost(NormalizeHost("[" + match.Groups["ip6"].Value + "]"), fromUrl: false);
            }
            else
            {
                description = ClassifyHostname(match.Groups["name"].Value.ToLowerInvariant(), fromUrl: false);
            }

            if (description is not null)
                return description;
        }

        return MetadataPattern.IsMatchOrFalse(text) ? CloudMetadata : null;
    }

    private static bool IsSpecialScheme(string scheme) =>
        scheme.Equals("http", StringComparison.OrdinalIgnoreCase)
        || scheme.Equals("https", StringComparison.OrdinalIgnoreCase)
        || scheme.Equals("ws", StringComparison.OrdinalIgnoreCase)
        || scheme.Equals("wss", StringComparison.OrdinalIgnoreCase)
        || scheme.Equals("ftp", StringComparison.OrdinalIgnoreCase);

    /// <summary>Classifies the host of the authority that starts at <paramref name="start"/>.</summary>
    private static string? CheckAuthority(string text, int start)
    {
        // the search is bounded, so a run of scheme-like prefixes with no terminator in sight costs
        // at most MaxAuthorityLength each rather than the rest of the text
        var window = Math.Min(text.Length - start, MaxAuthorityLength + 1);
        var length = text.AsSpan(start, window).IndexOfAny(AuthorityTerminators);
        if (length < 0)
            length = window;

        if (length == 0 || length > MaxAuthorityLength)
            return null;

        var authority = text.AsSpan(start, length);

        // the host follows the last '@'; everything before it is userinfo
        var at = authority.LastIndexOf('@');
        if (at >= 0)
            authority = authority[(at + 1)..];

        ReadOnlySpan<char> host;
        if (authority.Length > 0 && authority[0] == '[')
        {
            var close = authority.IndexOf(']');
            if (close < 0)
                return null;

            host = authority[..(close + 1)];
        }
        else
        {
            var colon = authority.IndexOf(':');
            host = (colon >= 0 ? authority[..colon] : authority).TrimEnd(']');
        }

        return ClassifyHost(NormalizeHost(host.ToString()), fromUrl: true);
    }

    /// <summary>
    /// Percent-decodes, width-folds and lowercases a host, and drops one trailing dot - the forms a
    /// URL parser treats as the same host.
    /// </summary>
    private static string NormalizeHost(string host)
    {
        var decoded = PercentDecoder.Decode(host);

        if (!Ascii.IsValid(decoded))
        {
            try
            {
                // compatibility folding maps fullwidth and enclosed forms to ASCII, as IDNA mapping does
                decoded = decoded.Normalize(NormalizationForm.FormKC).Replace('。', '.');
            }
            catch (ArgumentException)
            {
                // not normalizable (a lone surrogate); classify it as written
            }
        }

        decoded = decoded.ToLowerInvariant();

        return decoded.Length > 1 && decoded[^1] == '.' ? decoded[..^1] : decoded;
    }

    private static string? ClassifyHost(string host, bool fromUrl)
    {
        if (host.Length == 0)
            return null;

        if (host[0] == '[')
        {
            if (host[^1] != ']')
                return null;

            return IPAddress.TryParse(host.AsSpan(1, host.Length - 2), out var v6) && v6.AddressFamily == AddressFamily.InterNetworkV6
                ? ClassifyAddress(v6)
                : null;
        }

        if (LooksLikeIPv4(host) && IPAddress.TryParse(host, out var v4) && v4.AddressFamily == AddressFamily.InterNetwork)
            return ClassifyAddress(v4);

        return ClassifyHostname(host, fromUrl);
    }

    // the character set of every IPv4 form IPAddress accepts: decimal, octal and 0x-prefixed hex parts
    private static bool LooksLikeIPv4(string host)
    {
        if (!char.IsAsciiDigit(host[0]))
            return false;

        foreach (var c in host)
        {
            if (!char.IsAsciiHexDigit(c) && c != '.' && c != 'x' && c != 'X')
                return false;
        }

        return true;
    }

    private static string? ClassifyHostname(string host, bool fromUrl)
    {
        if (host == "localhost" || host.EndsWith(".localhost", StringComparison.Ordinal))
            return Localhost;

        // the short metadata names resolve through the cloud's search domain; outside a URL they are
        // ordinary words
        if (host is "metadata.google.internal" or "instance-data.ec2.internal"
            || (fromUrl && host is "metadata" or "instance-data"))
        {
            return CloudMetadata;
        }

        foreach (var suffix in InternalSuffixes)
        {
            if (host.EndsWith(suffix, StringComparison.Ordinal) && host.Length > suffix.Length)
                return InternalHostname;
        }

        return null;
    }

    private static string? ClassifyAddress(IPAddress address)
    {
        if (address.AddressFamily == AddressFamily.InterNetworkV6)
            return ClassifyIPv6(address);

        Span<byte> b = stackalloc byte[4];
        if (!address.TryWriteBytes(b, out _))
            return null;

        if ((b[0], b[1], b[2], b[3]) is (169, 254, 169, 254) or (169, 254, 170, 2) or (100, 100, 100, 200) or (192, 0, 0, 192))
            return CloudMetadata;

        // 127/8 loopback; 0/8 "this network", which connects to the local host
        if (b[0] is 127 or 0)
            return Localhost;

        var isInternal = b[0] == 10
            || (b[0] == 172 && (b[1] & 0xF0) == 16)
            || (b[0] == 192 && b[1] == 168)
            || (b[0] == 169 && b[1] == 254)
            || (b[0] == 100 && (b[1] & 0xC0) == 64);

        return isInternal ? InternalNetwork : null;
    }

    private static string? ClassifyIPv6(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6)
            return ClassifyAddress(address.MapToIPv4());

        Span<byte> b = stackalloc byte[16];
        if (!address.TryWriteBytes(b, out _))
            return null;

        // ::/96: the unspecified address, loopback, or a deprecated IPv4-compatible address
        if (b[..12].IndexOfAnyExcept((byte)0) < 0)
        {
            if (b[12..15].IndexOfAnyExcept((byte)0) < 0 && b[15] is 0 or 1)
                return Localhost;

            return ClassifyAddress(new IPAddress(b[12..]));
        }

        // 64:ff9b::/96, the NAT64 well-known prefix, reaches the IPv4 address it carries
        if (b[0] == 0x00 && b[1] == 0x64 && b[2] == 0xFF && b[3] == 0x9B && b[4..12].IndexOfAnyExcept((byte)0) < 0)
            return ClassifyAddress(new IPAddress(b[12..]));

        // fd00:ec2::254, the AWS instance metadata service over IPv6
        if (b[0] == 0xFD && b[1] == 0x00 && b[2] == 0x0E && b[3] == 0xC2 && b[4..14].IndexOfAnyExcept((byte)0) < 0 && b[14] == 0x02 && b[15] == 0x54)
            return CloudMetadata;

        // fc00::/7 unique local, fe80::/10 link-local, fec0::/10 site-local
        var isInternal = (b[0] & 0xFE) == 0xFC || (b[0] == 0xFE && (b[1] & 0x80) == 0x80);

        return isInternal ? InternalNetwork : null;
    }
}
