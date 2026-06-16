namespace AgentGuard.Pii.Analyzer;

/// <summary>
/// Base class for all PII recognizers. A recognizer detects one or more entity types in text and
/// returns <see cref="RecognizerResult"/>s.
/// </summary>
public abstract class EntityRecognizer
{
    /// <summary>Minimum possible confidence score.</summary>
    public const double MinScore = 0;

    /// <summary>Maximum possible confidence score.</summary>
    public const double MaxScore = 1.0;

    private static int _idCounter;

    /// <summary>Initializes a new instance of the <see cref="EntityRecognizer"/> class.</summary>
    protected EntityRecognizer(
        IReadOnlyList<string> supportedEntities,
        string? name = null,
        string supportedLanguage = "en",
        IReadOnlyList<string>? context = null)
    {
        SupportedEntities = supportedEntities;
        SupportedLanguage = supportedLanguage;
        Name = name ?? GetType().Name;
        Context = context;
        Id = $"{Name}_{Interlocked.Increment(ref _idCounter)}";
    }

    /// <summary>The entity types this recognizer can detect.</summary>
    public IReadOnlyList<string> SupportedEntities { get; }

    /// <summary>The language this recognizer supports.</summary>
    public string SupportedLanguage { get; }

    /// <summary>The recognizer's display name.</summary>
    public string Name { get; }

    /// <summary>A process-unique identifier for this recognizer instance.</summary>
    public string Id { get; }

    /// <summary>Context words that, when found near a match, boost its confidence.</summary>
    public IReadOnlyList<string>? Context { get; }

    /// <summary>Analyzes <paramref name="text"/> for the requested <paramref name="entities"/>.</summary>
    public abstract IReadOnlyList<RecognizerResult> Analyze(string text, IReadOnlyList<string> entities);

    /// <summary>
    /// Removes duplicate and contained results, keeping the highest-scoring non-contained spans.
    /// </summary>
    public static List<RecognizerResult> RemoveDuplicates(IEnumerable<RecognizerResult> results)
    {
        // sort by descending score, then start, then descending span length
        var sorted = results
            .OrderByDescending(r => r.Score)
            .ThenBy(r => r.Start)
            .ThenByDescending(r => r.End - r.Start)
            .ToList();

        var filtered = new List<RecognizerResult>();
        foreach (var result in sorted)
        {
            if (result.Score == 0)
            {
                continue;
            }

            var keep = true;
            foreach (var existing in filtered)
            {
                if (result.ContainedIn(existing) && result.EntityType == existing.EntityType)
                {
                    keep = false;
                    break;
                }
            }

            if (keep)
            {
                filtered.Add(result);
            }
        }

        return filtered;
    }

    /// <summary>Applies the given search/replace pairs to <paramref name="text"/> in order.</summary>
    public static string SanitizeValue(string text, IReadOnlyList<(string Search, string Replacement)> replacementPairs)
    {
        foreach (var (search, replacement) in replacementPairs)
        {
            text = text.Replace(search, replacement, StringComparison.Ordinal);
        }

        return text;
    }
}
