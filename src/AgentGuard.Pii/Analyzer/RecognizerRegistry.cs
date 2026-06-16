namespace AgentGuard.Pii.Analyzer;

/// <summary>
/// Holds the set of <see cref="EntityRecognizer"/>s available to an <see cref="AnalyzerEngine"/> and
/// selects the relevant ones per request.
/// </summary>
public sealed class RecognizerRegistry
{
    private readonly List<EntityRecognizer> _recognizers;

    /// <summary>Initializes a new instance of the <see cref="RecognizerRegistry"/> class.</summary>
    public RecognizerRegistry(IEnumerable<EntityRecognizer>? recognizers = null)
    {
        _recognizers = recognizers?.ToList() ?? [];
    }

    /// <summary>All registered recognizers.</summary>
    public IReadOnlyList<EntityRecognizer> Recognizers => _recognizers;

    /// <summary>Adds a recognizer to the registry.</summary>
    public void AddRecognizer(EntityRecognizer recognizer) => _recognizers.Add(recognizer);

    /// <summary>
    /// Returns the recognizers supporting <paramref name="language"/> and, when
    /// <paramref name="entities"/> is provided, detecting at least one requested entity.
    /// </summary>
    public IReadOnlyList<EntityRecognizer> GetRecognizers(string language, IReadOnlyList<string>? entities = null)
    {
        var byLanguage = _recognizers.Where(r => r.SupportedLanguage == language);
        if (entities is null || entities.Count == 0)
        {
            return byLanguage.ToList();
        }

        var requested = new HashSet<string>(entities);
        return byLanguage.Where(r => r.SupportedEntities.Any(requested.Contains)).ToList();
    }

    /// <summary>Returns the distinct entity types supported across all recognizers for a language.</summary>
    public IReadOnlyList<string> GetSupportedEntities(string language) =>
        GetRecognizers(language).SelectMany(r => r.SupportedEntities).Distinct().ToList();
}
