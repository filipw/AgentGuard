namespace AgentGuard.Pii.Anonymizer.Operators;

/// <summary>Removes a PII span entirely (replaces it with an empty string).</summary>
public sealed class RedactOperator : IOperator
{
    /// <inheritdoc />
    public string Name => "redact";

    /// <inheritdoc />
    public OperatorType Type => OperatorType.Anonymize;

    /// <inheritdoc />
    public string Operate(string text, IReadOnlyDictionary<string, object> parameters) => string.Empty;

    /// <inheritdoc />
    public void Validate(IReadOnlyDictionary<string, object> parameters)
    {
    }
}
