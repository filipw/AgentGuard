using AgentGuard.Pii.Analyzer;

namespace AgentGuard.Pii.Batch;

/// <summary>
/// Runs an <see cref="AnalyzerEngine"/> over many values at once - a list of strings or a keyed
/// dictionary of records - returning results aligned with the input. For keyed records the key is
/// added to the detection context, so a value under <c>email</c> is scored as if "email" appeared
/// nearby.
/// <para>
/// Processing is sequential. The wrapped <see cref="AnalyzerEngine"/> keeps no mutable per-call state,
/// so a single instance may be shared across threads if a caller wants to parallelize externally.
/// </para>
/// </summary>
public sealed class BatchAnalyzerEngine
{
    private readonly AnalyzerEngine _analyzer;

    /// <summary>Initializes a new instance of the <see cref="BatchAnalyzerEngine"/> class.</summary>
    /// <param name="analyzer">The detection engine to run over each value. Required.</param>
    public BatchAnalyzerEngine(AnalyzerEngine analyzer)
    {
        ArgumentNullException.ThrowIfNull(analyzer);
        _analyzer = analyzer;
    }

    /// <summary>
    /// Analyzes each string in <paramref name="texts"/>, returning one result list per input in the
    /// same order. Null/whitespace entries yield an empty result list.
    /// </summary>
    public IReadOnlyList<IReadOnlyList<RecognizerResult>> Analyze(
        IEnumerable<string> texts,
        string language = "en",
        IReadOnlyList<string>? entities = null,
        double? scoreThreshold = null,
        IReadOnlyList<string>? allowList = null,
        AllowListMatch allowListMatch = AllowListMatch.Exact)
    {
        ArgumentNullException.ThrowIfNull(texts);

        var results = new List<IReadOnlyList<RecognizerResult>>();
        foreach (var text in texts)
        {
            results.Add(AnalyzeOne(text, language, entities, scoreThreshold, allowList, allowListMatch, context: null));
        }

        return results;
    }

    /// <summary>
    /// Analyzes each value in <paramref name="records"/>, preserving the keys. Each record's key is
    /// appended to the detection context.
    /// </summary>
    public IReadOnlyDictionary<string, IReadOnlyList<RecognizerResult>> Analyze(
        IReadOnlyDictionary<string, string> records,
        string language = "en",
        IReadOnlyList<string>? entities = null,
        double? scoreThreshold = null,
        IReadOnlyList<string>? allowList = null,
        AllowListMatch allowListMatch = AllowListMatch.Exact)
    {
        ArgumentNullException.ThrowIfNull(records);

        var results = new Dictionary<string, IReadOnlyList<RecognizerResult>>(records.Count, StringComparer.Ordinal);
        foreach (var (key, value) in records)
        {
            results[key] = AnalyzeOne(value, language, entities, scoreThreshold, allowList, allowListMatch, context: [key]);
        }

        return results;
    }

    private IReadOnlyList<RecognizerResult> AnalyzeOne(
        string? text,
        string language,
        IReadOnlyList<string>? entities,
        double? scoreThreshold,
        IReadOnlyList<string>? allowList,
        AllowListMatch allowListMatch,
        IReadOnlyList<string>? context)
    {
        if (string.IsNullOrWhiteSpace(text))
            return [];

        return _analyzer.Analyze(text, language, entities, scoreThreshold, allowList, allowListMatch, context);
    }
}
