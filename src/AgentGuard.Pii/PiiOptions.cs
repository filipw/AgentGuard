using AgentGuard.Pii.Analyzer;
using AgentGuard.Pii.Analyzer.Context;
using AgentGuard.Pii.Anonymizer;
using AgentGuard.Pii.Anonymizer.Operators;

namespace AgentGuard.Pii;

/// <summary>
/// Configures <see cref="PiiRule"/>: which entities to detect, how to anonymize them, the
/// detection threshold and allow-list behavior.
/// </summary>
public sealed class PiiOptions
{
    /// <summary>
    /// Entity types to detect. When null or empty, all supported entities are detected.
    /// Examples: <c>CREDIT_CARD</c>, <c>EMAIL_ADDRESS</c>, <c>US_SSN</c>, <c>IBAN_CODE</c>,
    /// <c>CRYPTO</c>, <c>IP_ADDRESS</c>, <c>URL</c>, <c>MAC_ADDRESS</c>, <c>PHONE_NUMBER</c>, <c>US_ITIN</c>.
    /// </summary>
    public IReadOnlyList<string>? Entities { get; init; }

    /// <summary>
    /// Per-entity anonymization operators. A <c>DEFAULT</c> entry applies to entities without a
    /// specific operator. When null, every entity is replaced with <c>&lt;ENTITY_TYPE&gt;</c>
    /// (unless <see cref="Replacement"/> is set).
    /// </summary>
    public IReadOnlyDictionary<string, OperatorConfig>? Operators { get; init; }

    /// <summary>
    /// Convenience flat replacement string applied to every entity (e.g. <c>[REDACTED]</c>). Ignored
    /// when <see cref="Operators"/> is provided.
    /// </summary>
    public string? Replacement { get; init; }

    /// <summary>Language of the analyzed text. Defaults to <c>en</c>.</summary>
    public string Language { get; init; } = "en";

    /// <summary>
    /// Country packs to enable in addition to the generic recognizers and the always-on US pack,
    /// by ISO 3166-1 alpha-2 code (e.g. <c>uk</c>, <c>de</c>, <c>in</c>, <c>it</c>, <c>es</c>).
    /// Country packs are opt-in because enabling every national identifier at once inflates false
    /// positives. When null or empty, only the generic and US recognizers run.
    /// </summary>
    public IReadOnlyList<string>? Countries { get; init; }

    /// <summary>How recognizer context words are matched against surrounding tokens. Defaults to substring.</summary>
    public ContextMatchingMode ContextMatchingMode { get; init; } = ContextMatchingMode.Substring;

    /// <summary>
    /// Minimum confidence for a detection to be acted on. Defaults to 0.4 so weak patterns without
    /// supporting context (e.g. a bare 9-digit number) are dropped.
    /// </summary>
    public double ScoreThreshold { get; init; } = 0.4;

    /// <summary>Terms to exempt from redaction.</summary>
    public IReadOnlyList<string>? AllowList { get; init; }

    /// <summary>How <see cref="AllowList"/> entries are interpreted. Defaults to exact match.</summary>
    public AllowListMatch AllowListMatch { get; init; } = AllowListMatch.Exact;

    /// <summary>Conflict resolution strategy for overlapping entities.</summary>
    public ConflictResolutionStrategy ConflictResolution { get; init; } = ConflictResolutionStrategy.MergeSimilarOrContained;

    /// <summary>When true (default), the rule also redacts model output, not just input.</summary>
    public bool RedactOutput { get; init; } = true;

    /// <summary>Builds the effective operator map from <see cref="Operators"/> / <see cref="Replacement"/>.</summary>
    internal IReadOnlyDictionary<string, OperatorConfig>? BuildOperators()
    {
        if (Operators is { Count: > 0 })
        {
            return Operators;
        }

        if (!string.IsNullOrEmpty(Replacement))
        {
            var parameters = new Dictionary<string, object> { [OperatorParams.NewValue] = Replacement };
            return new Dictionary<string, OperatorConfig> { ["DEFAULT"] = new("replace", parameters) };
        }

        return null;
    }
}
