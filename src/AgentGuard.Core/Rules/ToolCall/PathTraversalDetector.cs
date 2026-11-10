using System.Text;
using System.Text.RegularExpressions;

namespace AgentGuard.Core.Rules.ToolCall;

/// <summary>
/// Finds directory traversal, sensitive paths and NUL bytes in tool call arguments, in the argument
/// as written and in each percent-decoded form of it.
/// </summary>
/// <remarks>
/// Paths are normalized before matching as file APIs read them - backslashes become slashes, runs of
/// slashes collapse to one and <c>.</c> segments are dropped - so <c>..\</c>, <c>..//</c>,
/// <c>.././..</c> and mixed forms read the same as <c>../..</c>. A single plain <c>../</c> is an
/// ordinary relative path, so it takes two in a row (which is also what any path that climbs more
/// than one level above where it starts must contain); a traversal that only appears once the argument
/// is decoded is flagged on its own, since a legitimate path has no reason to encode one. Sensitive
/// paths are matched after <c>name/..</c> pairs are resolved as well, so <c>/etc/x/../passwd</c> reads
/// as <c>/etc/passwd</c>.
/// </remarks>
internal static class PathTraversalDetector
{
    internal const string Traversal = "Directory traversal (../)";
    internal const string EncodedTraversal = "Encoded directory traversal";
    internal const string SensitiveFile = "Absolute path to sensitive files";
    internal const string NulByte = "Null byte injection";

    private static readonly TimeSpan Timeout = TimeSpan.FromMilliseconds(200);

    // a parent-directory segment: "..", or "..;param" as servlet containers read it. The segment must
    // start a path component, and its parameter is bounded, which keeps the scan linear.
    private static readonly Regex ParentSegment = new(
        @"(?<![\w.~\-])\.\.(?>;[^/]{0,32})?(?=/|$)",
        RegexOptions.Compiled | RegexOptions.CultureInvariant, Timeout);

    // two parent-directory segments in a row
    private static readonly Regex ParentSegments = new(
        @"(?<![\w.~\-])\.\.(?>;[^/]{0,32})?/\.\.(?>;[^/]{0,32})?(?=/|$)",
        RegexOptions.Compiled | RegexOptions.CultureInvariant, Timeout);

    private static readonly Regex SensitivePath = new(
        @"/etc/(?:passwd|shadow|hosts)|/proc/self/|[a-z]:/windows/system32",
        RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, Timeout);

    // written-out NUL escapes: \x00, \u0000, and a \0 that does not start an octal escape or a
    // Windows path segment (C:\reports\2024\03\ holds a "\0" that is neither)
    private static readonly Regex NulEscape = new(
        @"\\(?:x00|u0000|0(?![0-9/\\]))",
        RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, Timeout);

    /// <summary>The patterns this detector runs, for warming.</summary>
    internal static IEnumerable<Regex> Patterns => [ParentSegment, ParentSegments, SensitivePath, NulEscape];

    /// <summary>Two parent-directory segments in a row in the argument as written.</summary>
    internal static bool HasTraversal(ArgumentText argument) =>
        ParentSegments.IsMatchOrFalse(NormalizeSeparators(argument.Raw));

    /// <summary>A parent-directory segment that only appears once the argument is decoded.</summary>
    internal static bool HasEncodedTraversal(ArgumentText argument)
    {
        if (argument.Decoded.Count == 0)
            return false;

        var written = CountParentSegments(NormalizeSeparators(argument.Raw));
        foreach (var decoded in argument.Decoded)
        {
            if (CountParentSegments(NormalizeSeparators(decoded)) > written)
                return true;
        }

        return false;
    }

    /// <summary>An absolute path to a well-known sensitive file, as written or decoded.</summary>
    internal static bool HasSensitivePath(ArgumentText argument) =>
        argument.AnyForm(text => SensitivePath.IsMatchOrFalse(ResolveParentSegments(NormalizeSeparators(text))));

    /// <summary>A NUL character or a written-out NUL escape, as written or decoded.</summary>
    internal static bool HasNulByte(ArgumentText argument) =>
        argument.AnyForm(text => text.Contains('\0') || NulEscape.IsMatchOrFalse(text));

    /// <summary>
    /// Replaces backslashes with slashes, collapses runs of slashes into one and drops <c>.</c>
    /// segments.
    /// </summary>
    internal static string NormalizeSeparators(string text)
    {
        if (text.IndexOf('\\') < 0 && !text.Contains("//", StringComparison.Ordinal) && !HasCurrentDirectorySegment(text))
            return text;

        var builder = new StringBuilder(text.Length);
        foreach (var c in text)
        {
            var normalized = c == '\\' ? '/' : c;
            if (normalized == '/' && builder.Length > 0 && builder[^1] == '/')
                continue;

            // a "." segment is dropped together with the slash that ends it: "a/./b" reads "a/b"
            if (normalized == '/' && EndsWithCurrentDirectorySegment(builder))
            {
                builder.Length--;
                continue;
            }

            builder.Append(normalized);
        }

        // a trailing "." segment: "a/." reads "a/"
        if (EndsWithCurrentDirectorySegment(builder))
            builder.Length--;

        return builder.ToString();
    }

    /// <summary>
    /// Resolves each <c>name/..</c> pair the way a file API does, in a text already passed through
    /// <see cref="NormalizeSeparators"/>. A <c>..</c> with nothing left to climb out of stays.
    /// </summary>
    internal static string ResolveParentSegments(string text)
    {
        if (!text.Contains("..", StringComparison.Ordinal))
            return text;

        var segments = text.Split('/');
        var kept = new List<string>(segments.Length);
        foreach (var segment in segments)
        {
            // the empty segment before a leading slash is the root and is never climbed out of
            if (segment == ".." && kept.Count > 0 && kept[^1] is not (".." or ""))
            {
                kept.RemoveAt(kept.Count - 1);
                continue;
            }

            kept.Add(segment);
        }

        return string.Join('/', kept);
    }

    // "." alone between separators (or the start or end of the text)
    private static bool HasCurrentDirectorySegment(string text)
    {
        for (var i = text.IndexOf('.'); i >= 0; i = text.IndexOf('.', i + 1))
        {
            var startsSegment = i == 0 || text[i - 1] is '/' or '\\';
            var endsSegment = i + 1 == text.Length || text[i + 1] is '/' or '\\';
            if (startsSegment && endsSegment)
                return true;
        }

        return false;
    }

    private static bool EndsWithCurrentDirectorySegment(StringBuilder builder) =>
        builder.Length > 0 && builder[^1] == '.' && (builder.Length == 1 || builder[^2] == '/');

    private static int CountParentSegments(string text) => ParentSegment.MatchesUntilTimeout(text).Count;
}
