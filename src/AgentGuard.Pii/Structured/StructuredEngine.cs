using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using AgentGuard.Pii.Analyzer;
using AgentGuard.Pii.Analyzer.Context;
using AgentGuard.Pii.Anonymizer;
using AgentGuard.Pii.Anonymizer.Operators;

namespace AgentGuard.Pii.Structured;

/// <summary>
/// Redacts PII in structured data - JSON documents and tabular CSV/TSV rows - by reusing the same
/// <see cref="AnalyzerEngine"/> and <see cref="AnonymizerEngine"/> as free-text redaction, preserving
/// the document shape and value types. Fully offline; supply a custom analyzer to enable country packs
/// or the optional ONNX NER recognizer.
/// </summary>
public sealed class StructuredEngine
{
    private readonly AnalyzerEngine _analyzer;
    private readonly AnonymizerEngine _anonymizer;
    private readonly string _language;
    private readonly double _scoreThreshold;
    private readonly ConflictResolutionStrategy _conflictResolution;

    /// <summary>Initializes a new instance of the <see cref="StructuredEngine"/> class.</summary>
    /// <param name="analyzer">Detection engine. Defaults to the generic + always-on US recognizers for <paramref name="language"/>.</param>
    /// <param name="anonymizer">Anonymization engine. Defaults to a fresh <see cref="AnonymizerEngine"/>.</param>
    /// <param name="language">Analysis language. Defaults to <c>en</c>.</param>
    /// <param name="scoreThreshold">Minimum detection confidence to act on. Defaults to 0.4.</param>
    /// <param name="conflictResolution">Overlap resolution strategy.</param>
    public StructuredEngine(
        AnalyzerEngine? analyzer = null,
        AnonymizerEngine? anonymizer = null,
        string language = "en",
        double scoreThreshold = 0.4,
        ConflictResolutionStrategy conflictResolution = ConflictResolutionStrategy.MergeSimilarOrContained)
    {
        _language = language;
        _scoreThreshold = scoreThreshold;
        _conflictResolution = conflictResolution;
        _analyzer = analyzer ?? new AnalyzerEngine(
            PiiRecognizers.CreateDefaultRegistry(language),
            new LemmaContextAwareEnhancer());
        _anonymizer = anonymizer ?? new AnonymizerEngine();
    }

    /// <summary>
    /// Redacts PII in the string values of a JSON document, preserving its structure and non-string
    /// types. Use <paramref name="scope"/> to restrict analysis to specific key paths.
    /// </summary>
    /// <param name="json">The JSON document.</param>
    /// <param name="scope">Optional path allow/deny list. When null, every string value is analyzed.</param>
    /// <param name="operators">Per-entity anonymization operators (with an optional <c>DEFAULT</c>).</param>
    /// <param name="writeIndented">When true, the output is pretty-printed.</param>
    public string AnonymizeJson(
        string json,
        JsonRedactionScope? scope = null,
        IReadOnlyDictionary<string, OperatorConfig>? operators = null,
        bool writeIndented = false)
    {
        ArgumentNullException.ThrowIfNull(json);

        var root = JsonNode.Parse(json);
        var effectiveScope = scope ?? new JsonRedactionScope();
        var redacted = Redact(root, string.Empty, effectiveScope, operators);

        // relaxed escaping keeps redaction tags (<EMAIL_ADDRESS>) and non-ASCII text readable in the
        // output; the result is still valid JSON.
        var serializerOptions = new JsonSerializerOptions
        {
            WriteIndented = writeIndented,
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        };

        return redacted is null ? "null" : redacted.ToJsonString(serializerOptions);
    }

    private JsonNode? Redact(
        JsonNode? node,
        string path,
        JsonRedactionScope scope,
        IReadOnlyDictionary<string, OperatorConfig>? operators)
    {
        switch (node)
        {
            case null:
                return null;

            case JsonObject obj:
                var newObj = new JsonObject();
                foreach (var (key, value) in obj)
                {
                    var childPath = path.Length == 0 ? key : $"{path}.{key}";
                    newObj[key] = Redact(value, childPath, scope, operators);
                }

                return newObj;

            case JsonArray arr:
                var newArr = new JsonArray();
                foreach (var item in arr)
                    newArr.Add(Redact(item, path, scope, operators)); // array elements share the parent path

                return newArr;

            case JsonValue val when val.GetValueKind() == JsonValueKind.String:
                var text = val.GetValue<string>();
                if (!string.IsNullOrEmpty(text) && scope.ShouldAnalyze(path))
                    return JsonValue.Create(AnonymizeText(text, operators));

                return JsonValue.Create(text);

            default:
                // numbers, booleans, and any other leaf are passed through unchanged
                return node.DeepClone();
        }
    }

    /// <summary>
    /// Redacts PII in tabular data column by column. Each column is sampled to infer whether it
    /// carries PII; cells in PII columns are analyzed and anonymized, while benign columns (and any in
    /// <see cref="StructuredCsvOptions.ExcludeColumns"/>) are left untouched. Header and row shape are
    /// preserved. Works for CSV or TSV - the caller supplies already-split cells.
    /// </summary>
    /// <param name="header">The column names.</param>
    /// <param name="rows">The data rows, each aligned with <paramref name="header"/>.</param>
    /// <param name="options">Sampling, inference, and per-entity operator configuration.</param>
    public StructuredCsvResult AnonymizeCsv(
        IReadOnlyList<string> header,
        IEnumerable<IReadOnlyList<string>> rows,
        StructuredCsvOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(header);
        ArgumentNullException.ThrowIfNull(rows);
        options ??= new StructuredCsvOptions();

        var materialized = rows.Select(r => r.ToArray()).ToList();
        var columnCount = header.Count;

        var include = options.IncludeColumns is { Count: > 0 }
            ? new HashSet<string>(options.IncludeColumns, StringComparer.Ordinal)
            : null;
        var exclude = options.ExcludeColumns is { Count: > 0 }
            ? new HashSet<string>(options.ExcludeColumns, StringComparer.Ordinal)
            : null;

        var columnEntities = new Dictionary<string, string>(StringComparer.Ordinal);

        for (var col = 0; col < columnCount; col++)
        {
            var name = header[col];

            if (exclude is not null && exclude.Contains(name))
                continue;

            var forced = include is not null && include.Contains(name);
            var (isPii, dominant) = InferColumn(materialized, col, options, forced);
            if (!isPii)
                continue;

            // a forced column with no detectable PII has an empty dominant type; redacting its cells is
            // a harmless no-op, but don't report a meaningless empty entity type to the caller.
            if (dominant.Length > 0)
                columnEntities[name] = dominant;

            foreach (var row in materialized)
            {
                if (col >= row.Length || string.IsNullOrEmpty(row[col]))
                    continue;

                row[col] = AnonymizeText(row[col], options.Operators);
            }
        }

        var resultRows = materialized.Select(r => (IReadOnlyList<string>)r).ToList();
        return new StructuredCsvResult(header, resultRows, columnEntities);
    }

    // sample up to SampleSize non-empty cells; a column is PII when at least MinPiiCellRatio of them
    // contain a detection (or when forced via IncludeColumns). dominant = most common entity type.
    private (bool IsPii, string Dominant) InferColumn(
        List<string[]> rows,
        int col,
        StructuredCsvOptions options,
        bool forced)
    {
        var nonEmpty = 0;
        var cellsWithPii = 0;
        var typeCounts = new Dictionary<string, int>(StringComparer.Ordinal);

        foreach (var row in rows)
        {
            if (nonEmpty >= options.SampleSize)
                break;
            if (col >= row.Length || string.IsNullOrWhiteSpace(row[col]))
                continue;

            nonEmpty++;
            var results = _analyzer.Analyze(row[col], _language, scoreThreshold: _scoreThreshold);
            if (results.Count == 0)
                continue;

            cellsWithPii++;
            foreach (var r in results)
                typeCounts[r.EntityType] = typeCounts.GetValueOrDefault(r.EntityType) + 1;
        }

        var dominant = typeCounts.Count == 0
            ? string.Empty
            : typeCounts.OrderByDescending(kvp => kvp.Value).ThenBy(kvp => kvp.Key, StringComparer.Ordinal).First().Key;

        if (forced)
            return (true, dominant);

        if (nonEmpty == 0)
            return (false, string.Empty);

        var ratio = (double)cellsWithPii / nonEmpty;
        return (ratio >= options.MinPiiCellRatio && dominant.Length > 0, dominant);
    }

    private string AnonymizeText(string text, IReadOnlyDictionary<string, OperatorConfig>? operators)
    {
        if (string.IsNullOrWhiteSpace(text))
            return text;

        var results = _analyzer.Analyze(text, _language, scoreThreshold: _scoreThreshold);
        if (results.Count == 0)
            return text;

        return _anonymizer.Anonymize(text, results, operators, _conflictResolution).Text;
    }
}
