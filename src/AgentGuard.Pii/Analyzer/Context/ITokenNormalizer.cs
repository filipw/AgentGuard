namespace AgentGuard.Pii.Analyzer.Context;

/// <summary>
/// Tokenizes text and produces normalized (stemmed/lemmatized, lowercased) forms used by
/// <see cref="LemmaContextAwareEnhancer"/> to match context words. Implementations are offline and
/// dependency-free so the analyzer never reaches out for a model.
/// </summary>
public interface ITokenNormalizer
{
    /// <summary>
    /// Splits <paramref name="text"/> into tokens, returning each token's surface form and its
    /// start (inclusive) and end (exclusive) offsets in the original text.
    /// </summary>
    IReadOnlyList<(string Token, int Start, int End)> Tokenize(string text);

    /// <summary>Returns the normalized (lowercased stem/lemma) form of a single token.</summary>
    string Normalize(string token);

    /// <summary>Returns <c>true</c> if the token is a stop word that should not anchor context matching.</summary>
    bool IsStopWord(string token);

    /// <summary>Returns <c>true</c> if the token is punctuation rather than a word.</summary>
    bool IsPunctuation(string token);
}
