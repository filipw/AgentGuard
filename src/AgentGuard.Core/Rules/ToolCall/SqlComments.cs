using System.Text.RegularExpressions;

namespace AgentGuard.Core.Rules.ToolCall;

/// <summary>
/// Rewrites SQL block comments the way the database reads them, so keywords separated by a comment
/// instead of a space (<c>UNION/**/SELECT</c>) or wrapped in an executable one
/// (<c>/*!50000 UNION*/</c>) are seen as the statement they form.
/// </summary>
internal static class SqlComments
{
    private static readonly TimeSpan Timeout = TimeSpan.FromMilliseconds(200);

    // MySQL runs the body of "/*! ... */" and "/*!50000 ... */", so only the markers go; any other
    // block comment becomes the white space it stands for. A comment body is bounded, and an opener
    // with no close in reach is left as written.
    private static readonly Regex Comment = new(
        @"/\*!\d{0,6}|/\*(?:[^*]|\*(?!/)){0,256}\*/|\*/",
        RegexOptions.Compiled | RegexOptions.CultureInvariant, Timeout);

    /// <summary>The pattern this helper runs, for warming.</summary>
    internal static Regex Pattern => Comment;

    /// <summary>
    /// Returns <paramref name="text"/> with its block comments replaced by a space, or <c>null</c>
    /// when it holds none.
    /// </summary>
    internal static string? Strip(string text)
    {
        if (!text.Contains("/*", StringComparison.Ordinal))
            return null;

        return Comment.TryReplace(text, static _ => " ");
    }
}
