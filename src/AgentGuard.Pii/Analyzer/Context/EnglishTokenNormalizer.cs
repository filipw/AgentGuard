using System.Text.RegularExpressions;

namespace AgentGuard.Pii.Analyzer.Context;

/// <summary>
/// Default offline <see cref="ITokenNormalizer"/> for English. Tokenizes on word boundaries and
/// punctuation, lowercases and Porter-stems tokens, and recognizes a built-in stop-word list. This is
/// a dependency-free approximation of dictionary lemmatization, not a bit-exact match for it.
/// </summary>
public sealed partial class EnglishTokenNormalizer : ITokenNormalizer
{
    /// <summary>A shared, immutable instance.</summary>
    public static readonly EnglishTokenNormalizer Instance = new();

    private static readonly HashSet<string> StopWords = new(StringComparer.Ordinal)
    {
        "a", "about", "above", "after", "again", "against", "all", "am", "an", "and", "any", "are",
        "aren't", "as", "at", "be", "because", "been", "before", "being", "below", "between", "both",
        "but", "by", "can", "can't", "cannot", "could", "couldn't", "did", "didn't", "do", "does",
        "doesn't", "doing", "don't", "down", "during", "each", "few", "for", "from", "further", "had",
        "hadn't", "has", "hasn't", "have", "haven't", "having", "he", "her", "here", "hers", "herself",
        "him", "himself", "his", "how", "i", "if", "in", "into", "is", "isn't", "it", "its", "itself",
        "let's", "me", "more", "most", "must", "my", "myself", "no", "nor", "not", "of", "off", "on",
        "once", "only", "or", "other", "ought", "our", "ours", "ourselves", "out", "over", "own",
        "same", "shall", "she", "should", "shouldn't", "so", "some", "such", "than", "that", "the",
        "their", "theirs", "them", "themselves", "then", "there", "these", "they", "this", "those",
        "through", "to", "too", "under", "until", "up", "very", "was", "wasn't", "we", "were",
        "weren't", "what", "when", "where", "which", "while", "who", "whom", "why", "will", "with",
        "won't", "would", "wouldn't", "you", "your", "yours", "yourself", "yourselves",
    };

    /// <inheritdoc />
    public IReadOnlyList<(string Token, int Start, int End)> Tokenize(string text)
    {
        var tokens = new List<(string, int, int)>();
        foreach (Match m in TokenRegex().Matches(text))
        {
            tokens.Add((m.Value, m.Index, m.Index + m.Length));
        }

        return tokens;
    }

    /// <inheritdoc />
    public string Normalize(string token)
    {
        var lowered = token.ToLowerInvariant();
        if (lowered.Length == 0 || !ContainsLetter(lowered))
        {
            return lowered;
        }

        return PorterStemmer.Stem(lowered);
    }

    /// <inheritdoc />
    public bool IsStopWord(string token) => StopWords.Contains(token.ToLowerInvariant());

    /// <inheritdoc />
    public bool IsPunctuation(string token) => token.Length > 0 && !ContainsLetterOrDigit(token);

    private static bool ContainsLetter(string token)
    {
        foreach (var c in token)
        {
            if (char.IsLetter(c))
            {
                return true;
            }
        }

        return false;
    }

    private static bool ContainsLetterOrDigit(string token)
    {
        foreach (var c in token)
        {
            if (char.IsLetterOrDigit(c))
            {
                return true;
            }
        }

        return false;
    }

    // word runs (letters/digits/apostrophes) or single punctuation characters
    [GeneratedRegex(@"[\w']+|[^\w\s]")]
    private static partial Regex TokenRegex();
}
