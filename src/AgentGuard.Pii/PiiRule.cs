using AgentGuard.Core.Abstractions;
using AgentGuard.Pii.Analyzer;
using AgentGuard.Pii.Analyzer.Context;
using AgentGuard.Pii.Anonymizer;

namespace AgentGuard.Pii;

/// <summary>
/// Detects and de-identifies PII using validated recognizers (regex + checksum) and configurable
/// anonymization operators, with confidence scoring and overlap resolution. Runs at order 20 on
/// both input and output.
/// </summary>
public sealed class PiiRule : IGuardrailRule
{
    private readonly PiiOptions _options;
    private readonly AnalyzerEngine _analyzer;
    private readonly AnonymizerEngine _anonymizer;

    /// <summary>Initializes a new instance of the <see cref="PiiRule"/> class.</summary>
    /// <param name="options">Detection/anonymization configuration. Defaults to all entities, replace operator.</param>
    /// <param name="analyzer">Optional custom analyzer engine. Defaults to the Stage 1 recognizers.</param>
    /// <param name="anonymizer">Optional custom anonymizer engine.</param>
    public PiiRule(
        PiiOptions? options = null,
        AnalyzerEngine? analyzer = null,
        AnonymizerEngine? anonymizer = null)
    {
        _options = options ?? new PiiOptions();
        _analyzer = analyzer ?? new AnalyzerEngine(
            PiiRecognizers.CreateRegistry(_options.Language, _options.Countries),
            new LemmaContextAwareEnhancer(contextMatchingMode: _options.ContextMatchingMode));
        _anonymizer = anonymizer ?? new AnonymizerEngine();
    }

    /// <inheritdoc />
    public string Name => "pii";

    /// <inheritdoc />
    public GuardrailPhase Phase => _options.RedactOutput ? GuardrailPhase.Both : GuardrailPhase.Input;

    /// <inheritdoc />
    public int Order => 20;

    /// <inheritdoc />
    public ValueTask<GuardrailResult> EvaluateAsync(GuardrailContext context, CancellationToken cancellationToken = default)
    {
        var text = context.Text;
        if (string.IsNullOrWhiteSpace(text))
        {
            return ValueTask.FromResult(GuardrailResult.Passed());
        }

        var results = _analyzer.Analyze(
            text,
            language: _options.Language,
            entities: _options.Entities,
            scoreThreshold: _options.ScoreThreshold,
            allowList: _options.AllowList,
            allowListMatch: _options.AllowListMatch);

        if (results.Count == 0)
        {
            return ValueTask.FromResult(GuardrailResult.Passed());
        }

        var anonymized = _anonymizer.Anonymize(
            text,
            results,
            operators: _options.BuildOperators(),
            conflictResolution: _options.ConflictResolution);

        var detectedTypes = results.Select(r => r.EntityType).Distinct().OrderBy(t => t, StringComparer.Ordinal).ToList();
        var reason = $"PII detected and de-identified: {string.Join(", ", detectedTypes)}";

        var result = GuardrailResult.Modified(anonymized.Text, reason) with
        {
            RuleName = Name,
            Metadata = new Dictionary<string, object>
            {
                ["entityTypes"] = detectedTypes,
                ["entityCount"] = results.Count,
            },
        };

        return ValueTask.FromResult(result);
    }
}
