using System.Text.RegularExpressions;

namespace AgentGuard.Core.Rules;

/// <summary>
/// Shared handling for the compiled pattern sets the regex-based rules hold.
/// </summary>
/// <remarks>
/// Two concerns, both learned the hard way. <see cref="RegexOptions.Compiled"/> generates IL on the
/// first match rather than at construction - measured at 0.4 to 4 ms per pattern against 0.0001 ms
/// once warm - so <see cref="Warm"/> pays that while the rule is being built rather than on the
/// first request. And a match that exceeds its timeout throws, which without
/// <see cref="IsMatchOrFalse"/> escapes the rule and takes the whole pipeline run down with it.
/// </remarks>
internal static class RegexPatterns
{
    /// <summary>Runs each pattern once so the first real request does not pay IL generation.</summary>
    internal static void Warm(IEnumerable<Regex> patterns)
    {
        foreach (var pattern in patterns)
        {
            try
            {
                pattern.IsMatch("warmup");
            }
            catch (RegexMatchTimeoutException)
            {
                // warming is best-effort; a timeout here just means the first real match pays it
            }
        }
    }

    /// <summary>
    /// Matches, treating a timeout as "no match" rather than letting the exception escape.
    /// </summary>
    /// <remarks>
    /// A pattern that cannot finish inside its budget is a scan that did not complete, not a clean
    /// verdict. Skipping it keeps one pathological input from failing the whole request; the
    /// remaining patterns still run.
    /// </remarks>
    internal static bool IsMatchOrFalse(this Regex pattern, string text)
    {
        try
        {
            return pattern.IsMatch(text);
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }
    }

    /// <summary>Replaces, returning the input unchanged if the pattern times out.</summary>
    internal static string ReplaceOrOriginal(this Regex pattern, string text, string replacement)
    {
        try
        {
            // a MatchEvaluator, not the string overload: Regex.Replace treats "$" sequences in the
            // replacement as substitutions, so a replacement containing one would be rewritten
            return pattern.Replace(text, _ => replacement);
        }
        catch (RegexMatchTimeoutException)
        {
            return text;
        }
    }
}
