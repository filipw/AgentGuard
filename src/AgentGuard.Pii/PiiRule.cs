using AgentGuard.Core.Abstractions;
using TasmanianDevil;
using TasmanianDevil.Analyzer;
using TasmanianDevil.Analyzer.Context;
using TasmanianDevil.Anonymizer;

namespace AgentGuard.Pii;

/// <summary>
/// Detects and de-identifies PII using validated recognizers (regex + checksum) and configurable
/// anonymization operators, with confidence scoring and overlap resolution. Runs at order 20 on
/// both input and output.
/// </summary>
public sealed class PiiRule : IGuardrailRule, IDisposable
{
    private readonly PiiOptions _options;
    private readonly AnalyzerEngine _analyzer;
    private readonly AnonymizerEngine _anonymizer;
    private readonly IReadOnlyList<IDisposable> _ownedResources;
    private readonly PiiRuleOptions _ruleOptions;
    private bool _disposed;

    /// <summary>Initializes a new instance of the <see cref="PiiRule"/> class.</summary>
    /// <param name="options">Detection/anonymization configuration. Defaults to all entities, replace operator.</param>
    /// <param name="analyzer">Optional custom analyzer engine.</param>
    /// <param name="anonymizer">Optional custom anonymizer engine.</param>
    /// <param name="ownedResources">
    /// Resources whose lifetime this rule takes over - the ONNX NER bridge, or a remote detector
    /// holding an <see cref="System.Net.Http.HttpClient"/>. They are released by
    /// <see cref="Dispose"/>, which the policy calls when it is disposed. Recognizers reached only
    /// through a caller-supplied <paramref name="analyzer"/> are left alone.
    /// </param>
    /// <param name="ruleOptions">
    /// Guardrail-side settings (phase, span merging). Separate from <paramref name="options"/> on
    /// purpose - see <see cref="PiiRuleOptions"/>.
    /// </param>
    public PiiRule(
        PiiOptions? options = null,
        AnalyzerEngine? analyzer = null,
        AnonymizerEngine? anonymizer = null,
        IReadOnlyList<IDisposable>? ownedResources = null,
        PiiRuleOptions? ruleOptions = null)
    {
        _ownedResources = ownedResources ?? [];
        _ruleOptions = ruleOptions ?? new PiiRuleOptions();
        _options = options ?? new PiiOptions();
        _analyzer = analyzer ?? new AnalyzerEngine(
            PiiRecognizers.CreateRegistry(_options.Language, _options.Countries),
            new LemmaContextAwareEnhancer(contextMatchingMode: _options.ContextMatchingMode));
        _anonymizer = anonymizer ?? new AnonymizerEngine();
    }

    /// <inheritdoc />
    public string Name => "pii";

    /// <inheritdoc />
    public GuardrailPhase Phase => _ruleOptions.RedactOutput ? GuardrailPhase.Both : GuardrailPhase.Input;

    /// <inheritdoc />
    public int Order => 20;

    /// <inheritdoc />
    public async ValueTask<GuardrailResult> EvaluateAsync(GuardrailContext context, CancellationToken cancellationToken = default)
    {
        var text = context.Text;
        if (string.IsNullOrWhiteSpace(text))
        {
            return GuardrailResult.Passed();
        }

        // AnalyzeAsync resolves synchronously when the registry has no async recognizer (the default,
        // fully-offline configuration), so this is a zero-cost await in that case.
        var results = await _analyzer.AnalyzeAsync(
            text,
            language: _options.Language,
            entities: _options.Entities,
            scoreThreshold: _options.ScoreThreshold,
            allowList: _options.AllowList,
            allowListMatch: _options.AllowListMatch,
            ct: cancellationToken).ConfigureAwait(false);

        if (results.Count == 0)
        {
            return GuardrailResult.Passed();
        }

        var anonymized = _anonymizer.Anonymize(
            text,
            results,
            operators: _options.BuildOperators(),
            conflictResolution: _options.ConflictResolution,
            mergeEntitiesWithSpaces: _options.MergeEntitiesWithSpaces);

        var detectedTypes = results.Select(r => r.EntityType).Distinct().OrderBy(t => t, StringComparer.Ordinal).ToList();

        // detection alone is not a modification: a keep operator, or a conflict resolution that
        // drops every span, leaves the text untouched. Reporting Modified there disagreed with the
        // pipeline's own comparison and emitted a "modified" outcome for identical text.
        if (string.Equals(anonymized.Text, text, StringComparison.Ordinal))
        {
            return GuardrailResult.Passed() with
            {
                RuleName = Name,
                Metadata = new Dictionary<string, object>
                {
                    ["entityTypes"] = detectedTypes,
                    ["entityCount"] = results.Count,
                },
            };
        }

        var reason = $"PII detected and de-identified: {string.Join(", ", detectedTypes)}";

        return GuardrailResult.Modified(anonymized.Text, reason) with
        {
            RuleName = Name,
            Metadata = new Dictionary<string, object>
            {
                ["entityTypes"] = detectedTypes,
                ["entityCount"] = results.Count,
            },
        };
    }

    /// <summary>Releases the recognizers handed to this rule via <c>ownedResources</c>.</summary>
    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;

        foreach (var resource in _ownedResources)
        {
            resource.Dispose();
        }
    }
}
