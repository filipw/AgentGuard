using System.Text.RegularExpressions;
using AgentGuard.Pii.Analyzer.Context;

namespace AgentGuard.Pii.Analyzer;

/// <summary>How an allow-list entry is interpreted.</summary>
public enum AllowListMatch
{
    /// <summary>Allow only results whose text exactly equals an allow-list entry.</summary>
    Exact,

    /// <summary>Allow results whose text matches any allow-list entry interpreted as a regex.</summary>
    Regex,
}

/// <summary>
/// Orchestrates PII detection: runs recognizers, enhances scores using context, removes duplicates
/// and low-scoring results, and applies allow-lists.
/// </summary>
public sealed class AnalyzerEngine
{
    private readonly RecognizerRegistry _registry;
    private readonly IContextAwareEnhancer _contextAwareEnhancer;
    private readonly double _defaultScoreThreshold;

    /// <summary>Initializes a new instance of the <see cref="AnalyzerEngine"/> class.</summary>
    public AnalyzerEngine(
        RecognizerRegistry registry,
        IContextAwareEnhancer? contextAwareEnhancer = null,
        double defaultScoreThreshold = 0)
    {
        _registry = registry;
        _contextAwareEnhancer = contextAwareEnhancer ?? new LemmaContextAwareEnhancer();
        _defaultScoreThreshold = defaultScoreThreshold;
    }

    /// <summary>The recognizer registry backing this engine.</summary>
    public RecognizerRegistry Registry => _registry;

    /// <summary>Detects PII entities in <paramref name="text"/> for the given <paramref name="language"/>.</summary>
    public IReadOnlyList<RecognizerResult> Analyze(
        string text,
        string language = "en",
        IReadOnlyList<string>? entities = null,
        double? scoreThreshold = null,
        IReadOnlyList<string>? allowList = null,
        AllowListMatch allowListMatch = AllowListMatch.Exact,
        IReadOnlyList<string>? context = null)
    {
        var allFields = entities is null || entities.Count == 0;
        var recognizers = _registry.GetRecognizers(language, entities);

        var effectiveEntities = allFields
            ? _registry.GetSupportedEntities(language)
            : entities!;

        var results = new List<RecognizerResult>();
        foreach (var recognizer in recognizers)
        {
            var current = recognizer.Analyze(text, effectiveEntities);
            if (current.Count > 0)
            {
                AddRecognizerIdIfMissing(current, recognizer);
                results.AddRange(current);
            }
        }

        var enhanced = _contextAwareEnhancer.EnhanceUsingContext(text, results, recognizers, context).ToList();

        var deduped = EntityRecognizer.RemoveDuplicates(enhanced);
        var thresholded = RemoveLowScores(deduped, scoreThreshold);

        if (allowList is { Count: > 0 })
        {
            thresholded = RemoveAllowList(thresholded, allowList, text, allowListMatch);
        }

        return thresholded;
    }

    private List<RecognizerResult> RemoveLowScores(List<RecognizerResult> results, double? scoreThreshold)
    {
        var threshold = scoreThreshold ?? _defaultScoreThreshold;
        return results.Where(r => r.Score >= threshold).ToList();
    }

    private static List<RecognizerResult> RemoveAllowList(
        List<RecognizerResult> results,
        IReadOnlyList<string> allowList,
        string text,
        AllowListMatch allowListMatch)
    {
        if (allowListMatch == AllowListMatch.Regex)
        {
            var pattern = string.Join("|", allowList);
            var regex = new Regex(pattern, PatternRecognizer.DefaultRegexOptions, PatternRecognizer.DefaultTimeout);
            return results.Where(r =>
            {
                var word = text[r.Start..r.End];
                try
                {
                    return !regex.IsMatch(word);
                }
                catch (RegexMatchTimeoutException)
                {
                    return true;
                }
            }).ToList();
        }

        var allowed = new HashSet<string>(allowList, StringComparer.Ordinal);
        return results.Where(r => !allowed.Contains(text[r.Start..r.End])).ToList();
    }

    private static void AddRecognizerIdIfMissing(IReadOnlyList<RecognizerResult> results, EntityRecognizer recognizer)
    {
        foreach (var result in results)
        {
            result.RecognitionMetadata ??= new Dictionary<string, object>();
            if (!result.RecognitionMetadata.ContainsKey(RecognizerResult.RecognizerIdentifierKey))
            {
                result.RecognitionMetadata[RecognizerResult.RecognizerIdentifierKey] = recognizer.Id;
            }

            if (!result.RecognitionMetadata.ContainsKey(RecognizerResult.RecognizerNameKey))
            {
                result.RecognitionMetadata[RecognizerResult.RecognizerNameKey] = recognizer.Name;
            }
        }
    }
}
