namespace AgentGuard.Pii.Anonymizer;

/// <summary>
/// The result of a reversible de-identification: the anonymized text plus the per-span
/// <see cref="OperatorResult"/> items a caller can persist and later hand to
/// <see cref="DeanonymizerEngine.Deanonymize"/> to restore the original.
/// </summary>
public sealed class PiiDeidentificationResult
{
    /// <summary>Initializes a new instance of the <see cref="PiiDeidentificationResult"/> class.</summary>
    public PiiDeidentificationResult(string anonymizedText, IReadOnlyList<OperatorResult> items)
    {
        ArgumentNullException.ThrowIfNull(anonymizedText);
        ArgumentNullException.ThrowIfNull(items);
        AnonymizedText = anonymizedText;
        Items = items;
    }

    /// <summary>The anonymized (de-identified) text.</summary>
    public string AnonymizedText { get; }

    /// <summary>The per-span operations applied, in start order; the inputs needed to reverse.</summary>
    public IReadOnlyList<OperatorResult> Items { get; }

    /// <summary>
    /// <c>true</c> when every span was anonymized with a reversible operator (so the original can be
    /// restored in full); <c>false</c> if any span used a lossy operator (replace/redact/mask/hash/keep).
    /// </summary>
    public bool IsReversible => Items.All(i => DeanonymizerEngine.IsReversible(i.Operator));

    /// <summary>Wraps an <see cref="EngineResult"/> from <see cref="AnonymizerEngine.Anonymize"/>.</summary>
    public static PiiDeidentificationResult FromEngineResult(EngineResult result)
    {
        ArgumentNullException.ThrowIfNull(result);
        return new PiiDeidentificationResult(result.Text, result.Items);
    }
}
