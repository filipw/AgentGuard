using AgentGuard.Core.Rules.TopicBoundary;

namespace AgentGuard.Local.Classifiers;

/// <summary>
/// Lightweight keyword-overlap similarity provider for topic boundary enforcement.
/// For production, implement ITopicSimilarityProvider with a real embedding model.
/// </summary>
public sealed class KeywordSimilarityProvider : ITopicSimilarityProvider
{
    private readonly IDictionary<string, HashSet<string>> _topicKeywords;

    public KeywordSimilarityProvider(IDictionary<string, IEnumerable<string>>? topicKeywords = null)
    {
        _topicKeywords = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        if (topicKeywords is not null)
            foreach (var (topic, kw) in topicKeywords)
                _topicKeywords[topic] = new HashSet<string>(kw.Select(k => k.ToLowerInvariant()), StringComparer.OrdinalIgnoreCase);
    }

    public ValueTask<float> ComputeSimilarityAsync(string input, string topicDescriptor, CancellationToken cancellationToken = default)
    {
        var inputWords = Tokenize(input);
        var topicWords = GetTopicWords(topicDescriptor);
        if (inputWords.Count == 0 || topicWords.Count == 0) return ValueTask.FromResult(0f);
        var overlap = inputWords.Intersect(topicWords, StringComparer.OrdinalIgnoreCase).Count();
        return ValueTask.FromResult(Math.Min((float)overlap / topicWords.Count, 1f));
    }

    private HashSet<string> GetTopicWords(string desc)
    {
        if (_topicKeywords.TryGetValue(desc, out var cached)) return cached;
        var words = Tokenize(desc);
        _topicKeywords[desc] = words;
        return words;
    }

    private static HashSet<string> Tokenize(string text) =>
        new(text.ToLowerInvariant()
            .Split([' ', ',', '.', '!', '?', ';', ':', '-', '_', '(', ')', '"', '\'', '\n', '\r', '\t'], StringSplitOptions.RemoveEmptyEntries)
            .Where(w => w.Length > 2 && !StopWords.Contains(w)), StringComparer.OrdinalIgnoreCase);

    private static readonly HashSet<string> StopWords = new(StringComparer.OrdinalIgnoreCase)
    {
        "the","a","an","is","are","was","were","be","been","being","have","has","had","do","does","did",
        "will","would","shall","should","may","might","must","can","could","and","but","or","nor","not",
        "so","yet","for","with","about","from","into","out","off","over","under","this","that","what","how"
    };
}
