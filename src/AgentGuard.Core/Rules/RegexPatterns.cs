using System.Diagnostics.CodeAnalysis;
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
/// <para>
/// A third: the match timeout is wall-clock. It also counts time the thread spends not matching -
/// the JIT compiling a pattern's matching routine the first time a candidate position is found
/// (<see cref="Warm"/> only reaches the search for one), a garbage collection, a machine whose
/// processors are all busy. A timeout is therefore retried (<see cref="Attempts"/>): a stall does not
/// repeat, while a pattern that really cannot finish on the input times out again. Without the retry
/// a busy host skips patterns, and a skipped pattern is an input that was not checked.
/// </para>
/// </remarks>
internal static class RegexPatterns
{
    /// <summary>How many times a match is attempted before its timeout stands.</summary>
    internal const int Attempts = 2;

    /// <summary>
    /// A whole PEM private key block: the <c>-----BEGIN ... PRIVATE KEY-----</c> header (RSA, EC,
    /// DSA, OPENSSH, ENCRYPTED, plain PKCS#8, PGP's <c>PRIVATE KEY BLOCK</c> or <c>SECRET KEY BLOCK</c>,
    /// or the SSH2 <c>---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----</c> form), the key body including
    /// any headers such as <c>Proc-Type: 4,ENCRYPTED</c>, and the END line carrying the same label -
    /// or everything to the end of the text when that END line never comes.
    /// </summary>
    /// <remarks>
    /// An unterminated or mismatched block runs to the end of the text on purpose: over-redacting a
    /// truncated key is the safe failure. The body is a lazy scan that tests two alternatives per
    /// character, so the whole match is linear in the text length.
    /// </remarks>
    internal const string PemPrivateKeyBlock =
        @"-{4,5} ?BEGIN\s+(?<label>(?:[A-Z0-9]+\s+){0,3}(?:PRIVATE|SECRET)\s+KEY(?:\s+BLOCK)?) ?-{4,5}(?s:.*?)(?:-{4,5} ?END\s+\k<label> ?-{4,5}|\z)";

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
    internal static bool IsMatchOrFalse(this Regex pattern, string text) => pattern.TryIsMatch(text) ?? false;

    /// <summary>Matches, returning <c>null</c> when the pattern times out on every attempt.</summary>
    internal static bool? TryIsMatch(this Regex pattern, string text) =>
        TryRun((pattern, text), static s => s.pattern.IsMatch(s.text), out var matched) ? matched : null;

    /// <summary>
    /// Runs <paramref name="match"/>, again when it times out, up to <see cref="Attempts"/> times.
    /// Returns <c>false</c> when every attempt timed out.
    /// </summary>
    /// <param name="state">What <paramref name="match"/> works on, passed in so it needs no closure.</param>
    /// <param name="match">One attempt at the match.</param>
    /// <param name="result">What the attempt that finished returned.</param>
    internal static bool TryRun<TState, TResult>(TState state, Func<TState, TResult> match, [MaybeNullWhen(false)] out TResult result)
    {
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                result = match(state);
                return true;
            }
            catch (RegexMatchTimeoutException)
            {
                if (attempt >= Attempts)
                {
                    result = default;
                    return false;
                }
            }
        }
    }

    /// <summary>
    /// Finds the first match. Returns <c>false</c> when the pattern times out on every attempt;
    /// otherwise <paramref name="match"/> is the match, or <c>null</c> when there is none.
    /// </summary>
    internal static bool TryMatch(this Regex pattern, string text, out Match? match)
    {
        if (!TryRun((pattern, text), static s => s.pattern.Match(s.text), out var found))
        {
            match = null;
            return false;
        }

        match = found.Success ? found : null;
        return true;
    }

    /// <summary>
    /// Replaces every match with what <paramref name="evaluator"/> returns for it, or returns
    /// <c>null</c> when the pattern times out on every attempt.
    /// </summary>
    internal static string? TryReplace(this Regex pattern, string text, MatchEvaluator evaluator)
    {
        TryRun((pattern, text, evaluator), static s => s.pattern.Replace(s.text, s.evaluator), out var replaced);
        return replaced;
    }

    /// <summary>
    /// Collects every match. Returns <c>false</c> when the pattern times out on every attempt;
    /// <paramref name="matches"/> then holds what the last attempt found before its budget ran out.
    /// </summary>
    internal static bool TryMatches(this Regex pattern, string text, out List<Match> matches)
    {
        for (var attempt = 1; ; attempt++)
        {
            matches = [];

            try
            {
                for (var match = pattern.Match(text); match.Success; match = match.NextMatch())
                    matches.Add(match);

                return true;
            }
            catch (RegexMatchTimeoutException)
            {
                if (attempt >= Attempts)
                    return false;
            }
        }
    }

    /// <summary>Replaces, returning the input unchanged if the pattern times out.</summary>
    internal static string ReplaceOrOriginal(this Regex pattern, string text, string replacement)
    {
        // a MatchEvaluator, not the string overload: Regex.Replace treats "$" sequences in the
        // replacement as substitutions, so a replacement containing one would be rewritten
        return pattern.TryReplace(text, _ => replacement) ?? text;
    }

    /// <summary>
    /// Collects every match, stopping at a timeout rather than letting the exception escape. The
    /// matches found before the budget ran out are kept: each one is a real match.
    /// </summary>
    internal static List<Match> MatchesUntilTimeout(this Regex pattern, string text)
    {
        // when the scan could not finish, what it found so far still stands
        pattern.TryMatches(text, out var matches);
        return matches;
    }
}
