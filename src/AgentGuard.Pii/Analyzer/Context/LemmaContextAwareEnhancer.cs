namespace AgentGuard.Pii.Analyzer.Context;

/// <summary>How recognizer context words are matched against the normalized surrounding tokens.</summary>
public enum ContextMatchingMode
{
    /// <summary>Match a context word when it appears as a substring of a surrounding token (default).</summary>
    Substring,

    /// <summary>Match a context word only when it equals a surrounding token exactly.</summary>
    WholeWord,
}

/// <summary>
/// A context-aware enhancer that boosts a result's score when normalized (stemmed) keywords near the
/// match correspond to the recognizer's context words. It improves on plain surface-form matching by
/// normalizing both the surrounding tokens and the recognizer context words through an
/// <see cref="ITokenNormalizer"/>, and by filtering out stop words and punctuation. This is an offline
/// approximation of dictionary-lemma context matching, not a bit-exact equivalent.
/// </summary>
public sealed class LemmaContextAwareEnhancer : IContextAwareEnhancer
{
    private readonly double _contextSimilarityFactor;
    private readonly double _minScoreWithContextSimilarity;
    private readonly int _contextPrefixCount;
    private readonly int _contextSuffixCount;
    private readonly ContextMatchingMode _contextMatchingMode;
    private readonly ITokenNormalizer _normalizer;

    /// <summary>Initializes a new instance of the <see cref="LemmaContextAwareEnhancer"/> class.</summary>
    /// <param name="contextSimilarityFactor">Score increment applied on a context hit.</param>
    /// <param name="minScoreWithContextSimilarity">Floor a boosted score is raised to.</param>
    /// <param name="contextPrefixCount">Number of preceding keyword tokens inspected.</param>
    /// <param name="contextSuffixCount">Number of following keyword tokens inspected.</param>
    /// <param name="contextMatchingMode">Substring (default) or whole-word matching.</param>
    /// <param name="normalizer">Token normalizer. Defaults to <see cref="EnglishTokenNormalizer"/>.</param>
    public LemmaContextAwareEnhancer(
        double contextSimilarityFactor = 0.35,
        double minScoreWithContextSimilarity = 0.4,
        int contextPrefixCount = 5,
        int contextSuffixCount = 0,
        ContextMatchingMode contextMatchingMode = ContextMatchingMode.Substring,
        ITokenNormalizer? normalizer = null)
    {
        _contextSimilarityFactor = contextSimilarityFactor;
        _minScoreWithContextSimilarity = minScoreWithContextSimilarity;
        _contextPrefixCount = contextPrefixCount;
        _contextSuffixCount = contextSuffixCount;
        _contextMatchingMode = contextMatchingMode;
        _normalizer = normalizer ?? EnglishTokenNormalizer.Instance;
    }

    /// <inheritdoc />
    public IReadOnlyList<RecognizerResult> EnhanceUsingContext(
        string text,
        IReadOnlyList<RecognizerResult> rawResults,
        IReadOnlyList<EntityRecognizer> recognizers,
        IReadOnlyList<string>? externalContext = null)
    {
        var recognizerById = recognizers.ToDictionary(r => r.Id);
        var external = externalContext?.Select(w => _normalizer.Normalize(w)).ToList() ?? [];

        var tokens = BuildTokens(text);

        foreach (var result in rawResults)
        {
            if (result.RecognitionMetadata is null ||
                !result.RecognitionMetadata.TryGetValue(RecognizerResult.RecognizerIdentifierKey, out var idObj) ||
                idObj is not string id ||
                !recognizerById.TryGetValue(id, out var recognizer))
            {
                continue;
            }

            if (recognizer.Context is null || recognizer.Context.Count == 0)
            {
                continue;
            }

            if (result.RecognitionMetadata.TryGetValue(RecognizerResult.IsScoreEnhancedByContextKey, out var flag) && flag is true)
            {
                continue;
            }

            var surrounding = ExtractSurroundingWords(tokens, result.Start);
            surrounding.AddRange(external);

            var supportiveWord = FindSupportiveWord(surrounding, recognizer.Context);
            if (supportiveWord is not null)
            {
                result.Score += _contextSimilarityFactor;
                result.Score = Math.Max(result.Score, _minScoreWithContextSimilarity);
                result.Score = Math.Min(result.Score, EntityRecognizer.MaxScore);
                result.RecognitionMetadata[RecognizerResult.IsScoreEnhancedByContextKey] = true;
                result.AnalysisExplanation?.SetSupportiveContextWord(supportiveWord);
                result.AnalysisExplanation?.SetImprovedScore(result.Score);
            }
        }

        return rawResults;
    }

    private List<Token> BuildTokens(string text)
    {
        var raw = _normalizer.Tokenize(text);
        var tokens = new List<Token>(raw.Count);
        foreach (var (token, start, end) in raw)
        {
            var isKeyword = !_normalizer.IsPunctuation(token) && !_normalizer.IsStopWord(token);
            tokens.Add(new Token(_normalizer.Normalize(token), start, end, isKeyword));
        }

        return tokens;
    }

    private List<string> ExtractSurroundingWords(List<Token> tokens, int matchStart)
    {
        if (tokens.Count == 0)
        {
            return [];
        }

        // find the token whose span covers matchStart, or the first token at/after it
        var index = -1;
        for (var i = 0; i < tokens.Count; i++)
        {
            if (tokens[i].Start == matchStart || matchStart < tokens[i].End)
            {
                index = i;
                break;
            }
        }

        if (index < 0)
        {
            index = tokens.Count - 1;
        }

        var words = new HashSet<string>(StringComparer.Ordinal);

        // collect up to prefixCount keyword tokens backward (the entity token counts, hence + 1)
        CollectKeywords(tokens, index, _contextPrefixCount + 1, isBackward: true, words);

        // collect up to suffixCount keyword tokens forward (starts at the entity token, hence + 1)
        CollectKeywords(tokens, index, _contextSuffixCount + 1, isBackward: false, words);

        return words.ToList();
    }

    private static void CollectKeywords(List<Token> tokens, int index, int count, bool isBackward, HashSet<string> sink)
    {
        var i = index;
        var remaining = count;
        while (i >= 0 && i < tokens.Count && remaining > 0)
        {
            if (tokens[i].IsKeyword)
            {
                sink.Add(tokens[i].Normalized);
                remaining--;
            }

            i = isBackward ? i - 1 : i + 1;
        }
    }

    private string? FindSupportiveWord(IReadOnlyCollection<string> surroundingWords, IReadOnlyList<string> recognizerContext)
    {
        foreach (var contextWord in recognizerContext)
        {
            var normalizedContext = _normalizer.Normalize(contextWord);
            foreach (var word in surroundingWords)
            {
                var matched = _contextMatchingMode == ContextMatchingMode.WholeWord
                    ? string.Equals(word, normalizedContext, StringComparison.Ordinal)
                    : word.Contains(normalizedContext, StringComparison.Ordinal);

                if (matched)
                {
                    return contextWord;
                }
            }
        }

        return null;
    }

    private readonly record struct Token(string Normalized, int Start, int End, bool IsKeyword);
}
