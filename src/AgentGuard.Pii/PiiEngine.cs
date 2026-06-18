using AgentGuard.Pii.Analyzer;
using AgentGuard.Pii.Analyzer.Context;
using AgentGuard.Pii.Anonymizer;
using AgentGuard.Pii.Anonymizer.Operators;
using AgentGuard.Pii.Batch;
using AgentGuard.Pii.Structured;

namespace AgentGuard.Pii;

/// <summary>
/// A ready-to-use facade over the PII analyzer, anonymizer, deanonymizer, and the structured and
/// batch engines, configured once from a single <see cref="PiiOptions"/> - the same options object
/// that configures the <see cref="PiiRule"/> guardrail. Use this for direct (non-pipeline) PII work:
/// free text, reversible de-identification, structured JSON/CSV, and batch. Construct it once and
/// reuse it; the underlying engines build their recognizer registry eagerly and are safe to share
/// across threads.
/// </summary>
public sealed class PiiEngine
{
    private readonly PiiOptions _options;
    private readonly AnalyzerEngine _analyzer;
    private readonly AnonymizerEngine _anonymizer;
    private readonly DeanonymizerEngine _deanonymizer;
    private readonly StructuredEngine _structured;
    private readonly BatchAnalyzerEngine _batchAnalyzer;
    private readonly BatchAnonymizerEngine _batchAnonymizer;

    /// <summary>Initializes a new instance of the <see cref="PiiEngine"/> class.</summary>
    /// <param name="options">Detection/anonymization configuration. Defaults to all entities, replace operator.</param>
    /// <param name="analyzer">Optional custom analyzer engine. Defaults to the registry built from <paramref name="options"/>.</param>
    /// <param name="anonymizer">Optional custom anonymizer engine.</param>
    public PiiEngine(
        PiiOptions? options = null,
        AnalyzerEngine? analyzer = null,
        AnonymizerEngine? anonymizer = null)
    {
        _options = options ?? new PiiOptions();
        _analyzer = analyzer ?? new AnalyzerEngine(
            PiiRecognizers.CreateRegistry(_options.Language, _options.Countries),
            new LemmaContextAwareEnhancer(contextMatchingMode: _options.ContextMatchingMode));
        _anonymizer = anonymizer ?? new AnonymizerEngine();
        _deanonymizer = new DeanonymizerEngine();
        _structured = new StructuredEngine(_analyzer, _anonymizer, _options.Language, _options.ScoreThreshold, _options.ConflictResolution);
        _batchAnalyzer = new BatchAnalyzerEngine(_analyzer);
        _batchAnonymizer = new BatchAnonymizerEngine(_anonymizer);
    }

    /// <summary>Creates a <see cref="PiiEngine"/> for the given language and optional country packs.</summary>
    /// <param name="language">Analysis language. Defaults to <c>en</c>.</param>
    /// <param name="countries">Optional country packs to enable (e.g. <c>uk</c>, <c>de</c>).</param>
    public static PiiEngine Create(string language = "en", params string[] countries) =>
        new(new PiiOptions { Language = language, Countries = countries is { Length: > 0 } ? countries : null });

    /// <summary>Detects PII entities in <paramref name="text"/> without transforming it.</summary>
    public IReadOnlyList<RecognizerResult> Analyze(string text) =>
        string.IsNullOrEmpty(text)
            ? []
            : _analyzer.Analyze(text, _options.Language, _options.Entities, _options.ScoreThreshold, _options.AllowList, _options.AllowListMatch);

    /// <summary>Detects and anonymizes PII in <paramref name="text"/> using the configured operators.</summary>
    public EngineResult Anonymize(string text)
    {
        if (string.IsNullOrEmpty(text))
            return new EngineResult(text ?? string.Empty);

        var results = Analyze(text);
        return _anonymizer.Anonymize(text, results, _options.BuildOperators(), _options.ConflictResolution);
    }

    /// <summary>
    /// Anonymizes <paramref name="text"/> and returns a <see cref="PiiDeidentificationResult"/> whose
    /// items can be persisted and later passed to <see cref="Reidentify"/> to restore the original
    /// (when the configured operators are reversible, e.g. <c>encrypt</c>).
    /// </summary>
    public PiiDeidentificationResult Deidentify(string text) =>
        PiiDeidentificationResult.FromEngineResult(Anonymize(text));

    /// <summary>
    /// Reverses a prior <see cref="Deidentify"/> using the supplied reverse operators (default
    /// <c>decrypt</c>; supply the same key the spans were encrypted with).
    /// </summary>
    public EngineResult Reidentify(
        PiiDeidentificationResult deidentified,
        IReadOnlyDictionary<string, OperatorConfig> reverseOperators)
    {
        ArgumentNullException.ThrowIfNull(deidentified);
        return _deanonymizer.Deanonymize(deidentified.AnonymizedText, deidentified.Items, reverseOperators);
    }

    /// <summary>Redacts PII in the string values of a JSON document. See <see cref="StructuredEngine.AnonymizeJson"/>.</summary>
    public string AnonymizeJson(string json, JsonRedactionScope? scope = null, bool writeIndented = false) =>
        _structured.AnonymizeJson(json, scope, _options.BuildOperators(), writeIndented);

    /// <summary>Redacts PII in tabular data column by column. See <see cref="StructuredEngine.AnonymizeCsv"/>.</summary>
    public StructuredCsvResult AnonymizeCsv(
        IReadOnlyList<string> header,
        IEnumerable<IReadOnlyList<string>> rows,
        StructuredCsvOptions? csvOptions = null) =>
        _structured.AnonymizeCsv(header, rows, csvOptions ?? new StructuredCsvOptions { Operators = _options.BuildOperators() });

    /// <summary>Anonymizes each text in <paramref name="texts"/>, returning one result per input in order.</summary>
    public IReadOnlyList<EngineResult> AnonymizeBatch(IEnumerable<string> texts)
    {
        ArgumentNullException.ThrowIfNull(texts);
        var list = texts as IReadOnlyList<string> ?? texts.ToList();
        var detections = _batchAnalyzer.Analyze(list, _options.Language, _options.Entities, _options.ScoreThreshold, _options.AllowList, _options.AllowListMatch);
        return _batchAnonymizer.Anonymize(list, detections, _options.BuildOperators(), _options.ConflictResolution);
    }

    /// <summary>Anonymizes each value in <paramref name="records"/>, preserving the keys.</summary>
    public IReadOnlyDictionary<string, EngineResult> AnonymizeBatch(IReadOnlyDictionary<string, string> records)
    {
        ArgumentNullException.ThrowIfNull(records);
        var detections = _batchAnalyzer.Analyze(records, _options.Language, _options.Entities, _options.ScoreThreshold, _options.AllowList, _options.AllowListMatch);
        return _batchAnonymizer.Anonymize(records, detections, _options.BuildOperators(), _options.ConflictResolution);
    }
}
