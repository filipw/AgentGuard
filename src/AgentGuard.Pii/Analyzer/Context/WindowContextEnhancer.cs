using System.Text.RegularExpressions;

namespace AgentGuard.Pii.Analyzer.Context;

/// <summary>
/// A surface-form context-aware enhancer. It tokenizes the text on word boundaries and,
/// for each result, checks a window of preceding/following tokens against the recognizer's context
/// words (case-insensitive substring match), boosting the score when a context word is found.
/// This is a lemmatization-free approximation of a lemma-context-aware enhancer.
/// </summary>
public sealed partial class WindowContextEnhancer : IContextAwareEnhancer
{
    private readonly double _contextSimilarityFactor;
    private readonly double _minScoreWithContextSimilarity;
    private readonly int _contextPrefixCount;
    private readonly int _contextSuffixCount;

    /// <summary>Initializes a new instance of the <see cref="WindowContextEnhancer"/> class.</summary>
    public WindowContextEnhancer(
        double contextSimilarityFactor = 0.35,
        double minScoreWithContextSimilarity = 0.4,
        int contextPrefixCount = 5,
        int contextSuffixCount = 0)
    {
        _contextSimilarityFactor = contextSimilarityFactor;
        _minScoreWithContextSimilarity = minScoreWithContextSimilarity;
        _contextPrefixCount = contextPrefixCount;
        _contextSuffixCount = contextSuffixCount;
    }

    /// <inheritdoc />
    public IReadOnlyList<RecognizerResult> EnhanceUsingContext(
        string text,
        IReadOnlyList<RecognizerResult> rawResults,
        IReadOnlyList<EntityRecognizer> recognizers,
        IReadOnlyList<string>? externalContext = null)
    {
        var recognizerById = recognizers.ToDictionary(r => r.Id);
        var external = externalContext?.Select(w => w.ToLowerInvariant()).ToList() ?? [];

        var tokens = Tokenize(text);

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

            if (FindSupportiveWord(surrounding, recognizer.Context))
            {
                result.Score += _contextSimilarityFactor;
                result.Score = Math.Max(result.Score, _minScoreWithContextSimilarity);
                result.Score = Math.Min(result.Score, EntityRecognizer.MaxScore);
                result.RecognitionMetadata[RecognizerResult.IsScoreEnhancedByContextKey] = true;
                result.AnalysisExplanation?.SetImprovedScore(result.Score);
            }
        }

        return rawResults;
    }

    private List<string> ExtractSurroundingWords(List<(string Word, int Start, int End)> tokens, int matchStart)
    {
        if (tokens.Count == 0)
        {
            return [];
        }

        // find the token whose span covers matchStart, or the first token after it
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

        var words = new List<string>();

        // include the matched token itself plus n preceding tokens
        for (var i = index; i >= 0 && i > index - (_contextPrefixCount + 1); i--)
        {
            words.Add(tokens[i].Word.ToLowerInvariant());
        }

        for (var i = index + 1; i < tokens.Count && i <= index + _contextSuffixCount; i++)
        {
            words.Add(tokens[i].Word.ToLowerInvariant());
        }

        return words;
    }

    private static bool FindSupportiveWord(IReadOnlyList<string> surroundingWords, IReadOnlyList<string> recognizerContext)
    {
        foreach (var contextWord in recognizerContext)
        {
            var lowered = contextWord.ToLowerInvariant();
            foreach (var word in surroundingWords)
            {
                if (word.Contains(lowered, StringComparison.Ordinal))
                {
                    return true;
                }
            }
        }

        return false;
    }

    private static List<(string Word, int Start, int End)> Tokenize(string text)
    {
        var tokens = new List<(string, int, int)>();
        foreach (Match m in WordRegex().Matches(text))
        {
            tokens.Add((m.Value, m.Index, m.Index + m.Length));
        }

        return tokens;
    }

    [GeneratedRegex(@"\w+")]
    private static partial Regex WordRegex();
}
