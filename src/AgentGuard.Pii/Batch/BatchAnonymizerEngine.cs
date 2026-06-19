using AgentGuard.Pii.Analyzer;
using AgentGuard.Pii.Anonymizer;
using AgentGuard.Pii.Anonymizer.Operators;

namespace AgentGuard.Pii.Batch;

/// <summary>
/// Runs an <see cref="AnonymizerEngine"/> over many values at once, pairing each text with its
/// analyzer results. Provides a list form (aligned by position) and a keyed form (aligned by key),
/// the natural companions to <see cref="BatchAnalyzerEngine"/>.
/// <para>
/// Processing is sequential. The wrapped <see cref="AnonymizerEngine"/> keeps no mutable per-call
/// state, so a single instance may be shared across threads if a caller wants to parallelize externally.
/// </para>
/// </summary>
public sealed class BatchAnonymizerEngine
{
    private readonly AnonymizerEngine _anonymizer;

    /// <summary>Initializes a new instance of the <see cref="BatchAnonymizerEngine"/> class.</summary>
    /// <param name="anonymizer">The anonymization engine. Defaults to a fresh <see cref="AnonymizerEngine"/>.</param>
    public BatchAnonymizerEngine(AnonymizerEngine? anonymizer = null)
    {
        _anonymizer = anonymizer ?? new AnonymizerEngine();
    }

    /// <summary>
    /// Anonymizes each text in <paramref name="texts"/> using the matching entry in
    /// <paramref name="analyzerResults"/> (aligned by position), returning one result per input.
    /// </summary>
    /// <exception cref="ArgumentException">Thrown when the two lists differ in length.</exception>
    public IReadOnlyList<EngineResult> Anonymize(
        IReadOnlyList<string> texts,
        IReadOnlyList<IReadOnlyList<RecognizerResult>> analyzerResults,
        IReadOnlyDictionary<string, OperatorConfig>? operators = null,
        ConflictResolutionStrategy conflictResolution = ConflictResolutionStrategy.MergeSimilarOrContained)
    {
        ArgumentNullException.ThrowIfNull(texts);
        ArgumentNullException.ThrowIfNull(analyzerResults);
        if (texts.Count != analyzerResults.Count)
            throw new ArgumentException(
                $"texts ({texts.Count}) and analyzerResults ({analyzerResults.Count}) must have the same length.",
                nameof(analyzerResults));

        var results = new List<EngineResult>(texts.Count);
        for (var i = 0; i < texts.Count; i++)
        {
            results.Add(_anonymizer.Anonymize(texts[i], analyzerResults[i], operators, conflictResolution));
        }

        return results;
    }

    /// <summary>
    /// Anonymizes each value in <paramref name="texts"/> using the analyzer results under the same
    /// key, preserving the keys. Keys present in <paramref name="texts"/> but missing from
    /// <paramref name="analyzerResults"/> are treated as having no detections.
    /// </summary>
    public IReadOnlyDictionary<string, EngineResult> Anonymize(
        IReadOnlyDictionary<string, string> texts,
        IReadOnlyDictionary<string, IReadOnlyList<RecognizerResult>> analyzerResults,
        IReadOnlyDictionary<string, OperatorConfig>? operators = null,
        ConflictResolutionStrategy conflictResolution = ConflictResolutionStrategy.MergeSimilarOrContained)
    {
        ArgumentNullException.ThrowIfNull(texts);
        ArgumentNullException.ThrowIfNull(analyzerResults);

        var results = new Dictionary<string, EngineResult>(texts.Count, StringComparer.Ordinal);
        foreach (var (key, value) in texts)
        {
            var entityResults = analyzerResults.TryGetValue(key, out var r) ? r : [];
            results[key] = _anonymizer.Anonymize(value, entityResults, operators, conflictResolution);
        }

        return results;
    }
}
