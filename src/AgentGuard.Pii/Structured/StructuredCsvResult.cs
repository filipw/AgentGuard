namespace AgentGuard.Pii.Structured;

/// <summary>
/// The result of <see cref="StructuredEngine.AnonymizeCsv"/>: the (unchanged) header, the redacted
/// rows, and the dominant entity type inferred for each column that was redacted.
/// </summary>
public sealed class StructuredCsvResult
{
    /// <summary>Initializes a new instance of the <see cref="StructuredCsvResult"/> class.</summary>
    public StructuredCsvResult(
        IReadOnlyList<string> header,
        IReadOnlyList<IReadOnlyList<string>> rows,
        IReadOnlyDictionary<string, string> columnEntities)
    {
        Header = header;
        Rows = rows;
        ColumnEntities = columnEntities;
    }

    /// <summary>The header row, unchanged.</summary>
    public IReadOnlyList<string> Header { get; }

    /// <summary>The redacted data rows, aligned with <see cref="Header"/>.</summary>
    public IReadOnlyList<IReadOnlyList<string>> Rows { get; }

    /// <summary>The dominant entity type inferred for each column that was treated as PII.</summary>
    public IReadOnlyDictionary<string, string> ColumnEntities { get; }
}
