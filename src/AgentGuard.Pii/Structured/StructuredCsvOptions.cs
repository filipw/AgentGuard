using AgentGuard.Pii.Anonymizer.Operators;

namespace AgentGuard.Pii.Structured;

/// <summary>
/// Configures column-wise CSV/TSV redaction: which columns are processed, how many cells are sampled
/// to infer whether a column carries PII, and the per-entity anonymization operators.
/// </summary>
public sealed class StructuredCsvOptions
{
    /// <summary>Number of cells sampled per column to infer whether the column carries PII. Defaults to 100.</summary>
    public int SampleSize { get; init; } = 100;

    /// <summary>
    /// Minimum fraction of non-empty sampled cells that must contain a detection for a column to be
    /// treated as a PII column. Column inference suppresses redaction of mostly-benign columns even
    /// when an individual cell happens to look like PII. Defaults to 0.5.
    /// </summary>
    public double MinPiiCellRatio { get; init; } = 0.5;

    /// <summary>
    /// Per-entity anonymization operators (with an optional <c>DEFAULT</c>). When null, every detected
    /// entity is replaced with its <c>&lt;ENTITY_TYPE&gt;</c> tag.
    /// </summary>
    public IReadOnlyDictionary<string, OperatorConfig>? Operators { get; init; }

    /// <summary>
    /// When set, only these columns are redacted, bypassing inference (an explicit allowlist).
    /// </summary>
    public IReadOnlyList<string>? IncludeColumns { get; init; }

    /// <summary>Columns that are never redacted (a denylist), even if inference would flag them.</summary>
    public IReadOnlyList<string>? ExcludeColumns { get; init; }
}
