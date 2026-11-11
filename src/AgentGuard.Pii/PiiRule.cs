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
/// <remarks>
/// When a recognizer could not analyze the text (see <see cref="ReportRecognizerFailure"/>), the
/// result is an error shaped by <see cref="PiiRuleOptions.OnError"/>: the redactions the other
/// recognizers found are still applied, but the result has <see cref="GuardrailResult.IsError"/> set
/// instead of passing for text that was fully checked.
/// </remarks>
public sealed class PiiRule : IGuardrailRule, IDisposable
{
    // the failures recognizers report while the evaluation on the current async flow is analyzing
    private static readonly AsyncLocal<RecognizerFailures?> CurrentFailures = new();

    private readonly PiiOptions _options;
    private readonly IReadOnlyList<string>? _entities;
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
    /// Guardrail-side settings (the phase, what a recognizer failure does). Separate from
    /// <paramref name="options"/> on purpose - see <see cref="PiiRuleOptions"/>.
    /// </param>
    /// <exception cref="ArgumentException">
    /// <c>PiiOptions.Entities</c> names an entity type none of the analyzer's recognizers detect for the
    /// analysis language - a misspelling, or a country entity whose country pack is not enabled. The
    /// message lists the entity types that are detected. Names are matched ignoring case.
    /// </exception>
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

        // the engine quietly finds nothing for an entity type no recognizer detects, so a misspelled
        // name would switch that detection off; an empty list keeps the engine's own meaning
        _entities = _options.Entities is { Count: > 0 } entities
            ? PiiEntityNames.Resolve(
                entities, _analyzer.Registry.GetSupportedEntities(_options.Language), parameterName: nameof(options))
            : _options.Entities;
    }

    /// <inheritdoc />
    public string Name => "pii";

    /// <inheritdoc />
    public GuardrailPhase Phase => _ruleOptions.RedactOutput ? GuardrailPhase.Both : GuardrailPhase.Input;

    /// <inheritdoc />
    public int Order => 20;

    /// <summary>
    /// Tells the <see cref="PiiRule"/> evaluation in progress that a recognizer could not analyze the
    /// text it was given, so the evaluation ends as an error (see <see cref="PiiRuleOptions.OnError"/>)
    /// rather than as a clean result.
    /// </summary>
    /// <remarks>
    /// For recognizers that swallow their own failures so the remaining recognizers can still run -
    /// the out-of-process and Azure detectors do, and call this from their error callback. Call it on
    /// the async flow of the analysis (from within <c>Analyze</c> or <c>AnalyzeAsync</c>). Outside a
    /// <see cref="PiiRule"/> evaluation the call does nothing.
    /// </remarks>
    /// <param name="recognizer">A short name for the recognizer or service that failed, used in the error detail.</param>
    /// <param name="exception">The failure. Its type and message go into the result's <c>errorDetail</c>.</param>
    public static void ReportRecognizerFailure(string recognizer, Exception exception)
    {
        ArgumentNullException.ThrowIfNull(recognizer);
        ArgumentNullException.ThrowIfNull(exception);

        CurrentFailures.Value?.Add(Describe(recognizer, exception));
    }

    /// <inheritdoc />
    public async ValueTask<GuardrailResult> EvaluateAsync(GuardrailContext context, CancellationToken cancellationToken = default)
    {
        var text = context.Text;
        if (string.IsNullOrWhiteSpace(text))
        {
            return GuardrailResult.Passed();
        }

        // set before the analysis starts, so every recognizer it runs sees this evaluation's collector;
        // the change stays inside this async method and never reaches the caller's flow
        var failures = new RecognizerFailures();
        CurrentFailures.Value = failures;

        IReadOnlyList<RecognizerResult> results;
        try
        {
            // AnalyzeAsync resolves synchronously when the registry has no async recognizer (the default,
            // fully-offline configuration), so this is a zero-cost await in that case.
            results = await _analyzer.AnalyzeAsync(
                text,
                language: _options.Language,
                entities: _entities,
                scoreThreshold: _options.ScoreThreshold,
                allowList: _options.AllowList,
                allowListMatch: _options.AllowListMatch,
                ct: cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (cancellationToken.IsCancellationRequested && ex is not OperationCanceledException)
        {
            // a call torn down by the caller's cancellation can end with another exception; that is
            // still a cancellation, not a failure for OnError to turn into a block
            throw new OperationCanceledException("The PII analysis was canceled.", ex, cancellationToken);
        }
        catch (Exception ex) when (IsRecognizerFailure(ex, cancellationToken))
        {
            // nothing was analyzed, so there is no redacted text to let through
            return GuardrailResult.Error(Name, ErrorBehavior.FailClosed, Describe("PII analysis", ex)) with { RuleName = Name };
        }
        finally
        {
            CurrentFailures.Value = null;
        }

        // a recognizer that swallows failures also swallows the one its canceled call ends with
        cancellationToken.ThrowIfCancellationRequested();

        var failureDetail = failures.Describe();
        if (failureDetail is not null && _ruleOptions.OnError == ErrorBehavior.FailClosed)
        {
            return GuardrailResult.Error(Name, ErrorBehavior.FailClosed, failureDetail) with { RuleName = Name };
        }

        var outcome = Redact(text, results);
        return failureDetail is null ? outcome : WithFailure(outcome, failureDetail);
    }

    private GuardrailResult Redact(string text, IReadOnlyList<RecognizerResult> results)
    {
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

    // the redactions that were found still apply; the result says the detection behind them was incomplete
    private GuardrailResult WithFailure(GuardrailResult outcome, string failureDetail)
    {
        var error = GuardrailResult.Error(Name, _ruleOptions.OnError, failureDetail);

        var metadata = new Dictionary<string, object>(error.Metadata!);
        foreach (var (key, value) in outcome.Metadata ?? new Dictionary<string, object>())
        {
            metadata.TryAdd(key, value);
        }

        return error with
        {
            RuleName = Name,
            IsModified = outcome.IsModified,
            ModifiedText = outcome.ModifiedText,
            Reason = outcome.IsModified ? $"{outcome.Reason} (incomplete: a recognizer failed)" : error.Reason,
            Metadata = metadata,
        };
    }

    // an exception that escaped the analyzer is a recognizer failure for OnError only when the rule
    // fails closed; otherwise it propagates, as it would from a recognizer that is simply broken.
    // Using the rule after it was disposed is the caller's mistake and always propagates.
    private bool IsRecognizerFailure(Exception ex, CancellationToken cancellationToken) =>
        _ruleOptions.OnError == ErrorBehavior.FailClosed
        && !cancellationToken.IsCancellationRequested
        && ex is not ObjectDisposedException;

    private static string Describe(string source, Exception exception) =>
        $"{source} failed: {exception.GetType().Name}: {exception.Message}";

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

    /// <summary>What the recognizers of one evaluation reported, possibly from several threads.</summary>
    private sealed class RecognizerFailures
    {
        // enough to tell what went wrong without letting a long text's many windows flood the detail
        private const int MaxDescribed = 3;

        private readonly List<string> _details = [];

        public void Add(string detail)
        {
            lock (_details)
            {
                _details.Add(detail);
            }
        }

        public string? Describe()
        {
            lock (_details)
            {
                if (_details.Count == 0)
                    return null;

                var distinct = _details.Distinct(StringComparer.Ordinal).Take(MaxDescribed);
                var described = string.Join("; ", distinct);
                return _details.Count > 1 ? $"{described} ({_details.Count} failed calls)" : described;
            }
        }
    }
}
