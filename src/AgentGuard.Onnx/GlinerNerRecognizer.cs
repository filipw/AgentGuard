using AgentGuard.Pii.Analyzer;

namespace AgentGuard.Onnx;

/// <summary>
/// Offline, multilingual named-entity recognizer that detects the span entity types regex cannot
/// catch - <c>PERSON</c>, <c>LOCATION</c>, <c>ORGANIZATION</c>, <c>DATE_TIME</c> - and feeds them into
/// the order-20 PII pipeline as ordinary <see cref="RecognizerResult"/>s, so overlap resolution and
/// anonymization treat them uniformly with the regex/checksum entities.
/// <para>
/// Wraps a zero-shot span NER model (mDeBERTa-v3 backbone, label-conditioned span scoring) via a
/// pooled <see cref="GlinerModelSession"/>. The model carries its own confidence, so this recognizer
/// declares no surface-form context words and no country code. The model must be downloaded
/// separately - see <c>eng/download-gliner-model.sh</c>.
/// </para>
/// </summary>
public sealed class GlinerNerRecognizer : EntityRecognizer, IDisposable
{
    private readonly GlinerModelSession _session;
    private readonly GlinerNerOptions _options;

    // reverse map: AgentGuard entity type -> model prompt label (e.g. PERSON -> person)
    private readonly Dictionary<string, string> _entityToLabel;

    // forward map: model prompt label -> AgentGuard entity type (e.g. person -> PERSON)
    private readonly Dictionary<string, string> _labelToEntity;

    /// <summary>
    /// Creates a new NER recognizer. Loads (or reuses a pooled) ONNX session, the mDeBERTa
    /// SentencePiece tokenizer, and the model <c>config.json</c> from the paths in
    /// <paramref name="options"/>.
    /// </summary>
    /// <param name="options">Model paths, threshold, span width, and the label map.</param>
    /// <param name="supportedLanguage">Analysis language this recognizer is registered for. The model
    /// is multilingual; this only governs registry selection. Defaults to <c>en</c>.</param>
    /// <exception cref="ArgumentException">Thrown when a required path is missing or the threshold is out of range.</exception>
    /// <exception cref="FileNotFoundException">Thrown when a configured file does not exist.</exception>
    public GlinerNerRecognizer(GlinerNerOptions options, string supportedLanguage = "en")
        : base(BuildSupportedEntities(options), name: "GlinerNerRecognizer", supportedLanguage: supportedLanguage, context: null, countryCode: null)
    {
        ArgumentNullException.ThrowIfNull(options);

        var modelPath = RequireFile(options.ModelPath, nameof(options.ModelPath), "NER ONNX model");
        var tokenizerPath = RequireFile(options.TokenizerPath, nameof(options.TokenizerPath), "mDeBERTa SentencePiece tokenizer");
        var configPath = RequireFile(options.ConfigPath, nameof(options.ConfigPath), "NER config.json");

        if (options.NerThreshold is < 0f or > 1f)
            throw new ArgumentOutOfRangeException(nameof(options), "NerThreshold must be between 0.0 and 1.0.");

        _options = options;
        _entityToLabel = new Dictionary<string, string>(StringComparer.Ordinal);
        _labelToEntity = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (label, entity) in options.EntityLabelMap)
        {
            _labelToEntity[label] = entity;
            _entityToLabel[entity] = label;
        }

        _session = GlinerModelSession.Acquire(modelPath, tokenizerPath, configPath, options.MaxTokenLength, options.MaxSpanWidth, options.MaxChunkChars);
    }

    /// <summary>Internal constructor for testing - accepts a pre-built session.</summary>
    internal GlinerNerRecognizer(GlinerModelSession session, GlinerNerOptions options, string supportedLanguage = "en")
        : base(BuildSupportedEntities(options), name: "GlinerNerRecognizer", supportedLanguage: supportedLanguage, context: null, countryCode: null)
    {
        _session = session;
        _options = options;
        _entityToLabel = new Dictionary<string, string>(StringComparer.Ordinal);
        _labelToEntity = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (label, entity) in options.EntityLabelMap)
        {
            _labelToEntity[label] = entity;
            _entityToLabel[entity] = label;
        }
    }

    private static List<string> BuildSupportedEntities(GlinerNerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        return options.EntityLabelMap.Values.Distinct(StringComparer.Ordinal).ToList();
    }

    /// <inheritdoc />
    public override IReadOnlyList<RecognizerResult> Analyze(string text, IReadOnlyList<string> entities)
    {
        if (string.IsNullOrWhiteSpace(text))
            return [];

        // only prompt the model for labels whose mapped entity type the engine actually requested
        var requested = entities is { Count: > 0 } ? new HashSet<string>(entities, StringComparer.Ordinal) : null;
        var activeLabels = new List<string>();
        foreach (var entity in SupportedEntities)
        {
            if (requested is null || requested.Contains(entity))
                activeLabels.Add(_entityToLabel[entity]);
        }

        if (activeLabels.Count == 0)
            return [];

        var spans = _session.Predict(text, activeLabels, _options.NerThreshold);
        if (spans.Count == 0)
            return [];

        var results = new List<RecognizerResult>(spans.Count);
        foreach (var span in spans)
        {
            if (!_labelToEntity.TryGetValue(span.Label, out var entityType))
                continue;

            results.Add(new RecognizerResult(
                entityType,
                span.CharStart,
                span.CharEnd,
                span.Score,
                new Dictionary<string, object>
                {
                    [RecognizerResult.RecognizerNameKey] = Name,
                    [RecognizerResult.RecognizerIdentifierKey] = Id,
                    ["model"] = "gliner-multi-pii-mdeberta-v3",
                    ["modelLabel"] = span.Label,
                }));
        }

        return results;
    }

    private static string RequireFile(string? path, string paramName, string description)
    {
        if (string.IsNullOrWhiteSpace(path))
            throw new ArgumentException($"{description} path is required.", paramName);

        var full = Path.GetFullPath(path);
        if (!File.Exists(full))
            throw new FileNotFoundException($"{description} not found at '{full}'.", full);

        return full;
    }

    /// <summary>Releases this recognizer's reference to the pooled ONNX inference session.</summary>
    public void Dispose() => _session.Dispose();
}
