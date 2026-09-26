using System.Text;
using System.Text.RegularExpressions;

namespace AgentGuard.Core.Rules.Secrets;

/// <summary>
/// The <see cref="SecretCategory.GenericHighEntropy"/> check: random-looking tokens that none of
/// the specific patterns recognises.
/// </summary>
/// <remarks>
/// <para>
/// A token is random-looking when its Shannon entropy reaches a share of what a random string of
/// the same length and character set typically reaches (see
/// <see cref="SecretValues.ExpectedRandomEntropy"/>), so hex is measured against hex and a short
/// token against what its length allows.
/// </para>
/// <para>
/// Bare tokens need <see cref="SecretsDetectionOptions.MinHighEntropyLength"/> characters. A value
/// assigned to a secret-like key name (<c>db_password=...</c>, <c>"apiKey": "..."</c>) needs only
/// <see cref="KeyedMinLength"/> and less entropy, and is the only place hex strings and parts of
/// URLs are considered: bare hex is commit SHAs, hashes and ids far more often than it is a key.
/// UUIDs, placeholders, paths, words and identifiers, hashes labelled as such, base64 images and
/// data URIs, and JWT-like <c>eyJ...</c> strings (left to <see cref="SecretCategory.JwtToken"/>)
/// never count.
/// </para>
/// </remarks>
internal sealed class HighEntropyDetector
{
    /// <summary>Shortest value considered when it is assigned to a secret-like key name.</summary>
    internal const int KeyedMinLength = 12;

    // the share of a random string's typical entropy a token must reach; a value assigned to a
    // secret-like key name already has the key as evidence, so it needs less
    private const double BareThreshold = 0.9;
    private const double KeyedThreshold = 0.85;

    private const RegexOptions Options = RegexOptions.Compiled | RegexOptions.CultureInvariant;

    // base64 prefixes of image and document formats: data rather than credentials
    private static readonly string[] FileSignatures =
        ["iVBORw0KGgo", "/9j/", "R0lGOD", "UklGR", "JVBERi0", "UEsDB", "PHN2Zy"];

    private static readonly string[] HashLabels =
        ["sha1", "sha224", "sha256", "sha384", "sha512", "sha-1", "sha-256", "sha-384", "sha-512",
         "md5", "hash", "digest", "checksum", "etag", "fingerprint", "integrity"];

    private static readonly string[] SubresourceIntegrityPrefixes = ["sha1-", "sha256-", "sha384-", "sha512-"];

    private readonly Regex _tokenPattern;
    private readonly Regex _keyedValuePattern;
    private readonly Regex _excludedSpanPattern;

    /// <summary>Initializes a new instance of the <see cref="HighEntropyDetector"/> class.</summary>
    /// <param name="minLength">Shortest bare token considered.</param>
    /// <param name="timeout">Match timeout for each pattern.</param>
    public HighEntropyDetector(int minLength, TimeSpan timeout)
    {
        var keyedMinLength = Math.Min(KeyedMinLength, minLength);

        // '=' only as trailing base64 padding, so "name=value" is two tokens, not one
        _tokenPattern = new Regex(@"[A-Za-z0-9_\-/+]{" + minLength + ",}={0,2}", Options, timeout);

        // a key name ending in a secret-like word, a separator, and the value. The name can only
        // start where no name character precedes it and is at most 40 characters, which keeps the
        // scan linear.
        _keyedValuePattern = new Regex(
            @"(?i)(?<![A-Za-z0-9_.-])[A-Za-z0-9_.-]{0,40}?(?:key|secret|token|password|passwd|pwd|auth|credentials?)"
            + @"[""']?[^\S\r\n]*(?::|=>?)[^\S\r\n]*[""']?(?<value>[^\s""'`,;:&|<>(){}\[\]\\]{" + keyedMinLength + ",})",
            Options, timeout);

        // URLs, and JWT-like chains of base64url segments starting with eyJ
        _excludedSpanPattern = new Regex(
            @"(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]{0,20}://[^\s""'<>`]+|(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]*(?:\.[A-Za-z0-9_-]*){0,2}",
            Options, timeout);
    }

    /// <summary>The patterns the check runs, for warming and inspection.</summary>
    internal IEnumerable<Regex> Patterns => [_tokenPattern, _keyedValuePattern, _excludedSpanPattern];

    /// <summary>
    /// Looks for random-looking tokens in <paramref name="text"/>. With a
    /// <paramref name="replacement"/> every one found is replaced in <paramref name="rewritten"/>;
    /// without one the scan stops at the first.
    /// </summary>
    /// <remarks>
    /// A pattern that exceeds its match timeout ends the scan; what was found up to that point
    /// still counts, and is still replaced.
    /// </remarks>
    public bool Scan(string text, string? replacement, out string rewritten)
    {
        rewritten = text;
        var findings = new List<(int Start, int Length)>();
        var firstOnly = replacement is null;

        try
        {
            // values assigned to a secret-like key name come first: they are judged more leniently,
            // and the bare scan below skips them
            var keyedSpans = new List<(int Start, int End)>();
            foreach (Match match in _keyedValuePattern.Matches(text))
            {
                var value = match.Groups["value"];
                keyedSpans.Add((value.Index, value.Index + value.Length));
                if (IsRandom(text, value.Index, value.Length, keyed: true))
                {
                    findings.Add((value.Index, value.Length));
                    if (firstOnly)
                        return true;
                }
            }

            var excludedSpans = new List<(int Start, int End)>();
            foreach (Match match in _excludedSpanPattern.Matches(text))
                excludedSpans.Add((match.Index, match.Index + match.Length));

            var keyedIndex = 0;
            var excludedIndex = 0;
            foreach (Match match in _tokenPattern.Matches(text))
            {
                var (start, end) = (match.Index, match.Index + match.Length);
                if (Overlaps(keyedSpans, ref keyedIndex, start, end) || Overlaps(excludedSpans, ref excludedIndex, start, end))
                    continue;

                if (IsRandom(text, start, match.Length, keyed: false))
                {
                    findings.Add((start, match.Length));
                    if (firstOnly)
                        return true;
                }
            }
        }
        catch (RegexMatchTimeoutException)
        {
            // the scan could not finish inside its budget; keep what it found
        }

        if (findings.Count == 0 || replacement is null)
            return findings.Count > 0;

        findings.Sort((a, b) => a.Start.CompareTo(b.Start));
        var builder = new StringBuilder(text.Length);
        var copied = 0;
        foreach (var (start, length) in findings)
        {
            builder.Append(text, copied, start - copied).Append(replacement);
            copied = start + length;
        }

        rewritten = builder.Append(text, copied, text.Length - copied).ToString();
        return true;
    }

    /// <summary>
    /// Whether any span in <paramref name="spans"/> (sorted, non-overlapping) overlaps
    /// <c>[start, end)</c>. Callers ask in increasing order of <paramref name="start"/>, so
    /// <paramref name="index"/> only moves forward.
    /// </summary>
    private static bool Overlaps(List<(int Start, int End)> spans, ref int index, int start, int end)
    {
        while (index < spans.Count && spans[index].End <= start)
            index++;

        return index < spans.Count && spans[index].Start < end;
    }

    private static bool IsRandom(string text, int start, int length, bool keyed)
    {
        var token = text.AsSpan(start, length);

        // base64 of '{"': JWT segments and other encoded JSON, left to the JWT pattern
        if (token.StartsWith("eyJ", StringComparison.Ordinal))
            return false;

        if (SecretValues.IsPlaceholder(token)
            || SecretValues.LooksLikePath(token)
            || token.Contains("://", StringComparison.Ordinal)
            || SecretValues.IsUuid(token)
            || IsLabelledHash(text, start, token)
            || IsEncodedFile(text, start, token))
        {
            return false;
        }

        if (token.Length > 2 && token[0] == '0' && token[1] is 'x' or 'X' && SecretValues.IsHex(token[2..]))
            token = token[2..];

        // numbers are not keys, and bare hex is commit SHAs, hashes and ids far more often than
        // it is a credential
        if (!token.ContainsAnyInRange('a', 'z') && !token.ContainsAnyInRange('A', 'Z'))
            return false;

        if ((!keyed && SecretValues.IsHex(token)) || SecretValues.IsWordLike(token))
            return false;

        var threshold = keyed ? KeyedThreshold : BareThreshold;
        return SecretValues.ShannonEntropy(token) >= threshold * SecretValues.ExpectedRandomEntropy(token);
    }

    // a digest labelled as one ("sha256: 9f86...", "checksum=...") or in Subresource Integrity
    // form ("sha384-oqVu...")
    private static bool IsLabelledHash(string text, int start, ReadOnlySpan<char> token)
    {
        foreach (var prefix in SubresourceIntegrityPrefixes)
        {
            if (token.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        var before = text.AsSpan(Math.Max(0, start - 32), Math.Min(32, start)).TrimEnd(" \t\"':=");
        foreach (var label in HashLabels)
        {
            if (before.EndsWith(label, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    // the payload of a base64 data URI, or base64 that starts like an image or document file
    private static bool IsEncodedFile(string text, int start, ReadOnlySpan<char> token)
    {
        if (text.AsSpan(0, start).EndsWith("base64,", StringComparison.OrdinalIgnoreCase))
            return true;

        foreach (var signature in FileSignatures)
        {
            if (token.StartsWith(signature, StringComparison.Ordinal))
                return true;
        }

        return false;
    }
}
