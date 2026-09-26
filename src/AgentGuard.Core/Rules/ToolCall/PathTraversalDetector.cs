using System.Text;
using System.Text.RegularExpressions;

namespace AgentGuard.Core.Rules.ToolCall;

/// <summary>
/// Finds directory traversal, sensitive paths and NUL bytes in tool call arguments, in the argument
/// as written and in each percent-decoded form of it.
/// </summary>
/// <remarks>
/// Separators are normalized before matching - backslashes become slashes and runs of slashes
/// collapse to one, as file APIs treat them - so <c>..\</c>, <c>..//</c> and mixed forms read the
/// same as <c>../</c>. A single plain <c>../</c> is an ordinary relative path, so it takes two in a
/// row; a traversal that only appears once the argument is decoded is flagged on its own, since a
/// legitimate path has no reason to encode one.
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
        @"(?<![\w.~\-])\.\.(?:;[^/]{0,32})?(?=/|$)",
        RegexOptions.Compiled | RegexOptions.CultureInvariant, Timeout);

    // two parent-directory segments in a row
    private static readonly Regex ParentSegments = new(
        @"(?<![\w.~\-])\.\.(?:;[^/]{0,32})?/\.\.(?:;[^/]{0,32})?(?=/|$)",
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
        argument.AnyForm(text => SensitivePath.IsMatchOrFalse(NormalizeSeparators(text)));

    /// <summary>A NUL character or a written-out NUL escape, as written or decoded.</summary>
    internal static bool HasNulByte(ArgumentText argument) =>
        argument.AnyForm(text => text.Contains('\0') || NulEscape.IsMatchOrFalse(text));

    /// <summary>Replaces backslashes with slashes and collapses runs of slashes into one.</summary>
    internal static string NormalizeSeparators(string text)
    {
        if (text.IndexOf('\\') < 0 && !text.Contains("//", StringComparison.Ordinal))
            return text;

        var builder = new StringBuilder(text.Length);
        foreach (var c in text)
        {
            var normalized = c == '\\' ? '/' : c;
            if (normalized == '/' && builder.Length > 0 && builder[^1] == '/')
                continue;

            builder.Append(normalized);
        }

        return builder.ToString();
    }

    private static int CountParentSegments(string text) => ParentSegment.MatchesUntilTimeout(text).Count;
}
