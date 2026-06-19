namespace AgentGuard.Pii.Anonymizer.Operators;

/// <summary>Leaves a PII span unchanged (useful for tracking without anonymizing).</summary>
public sealed class KeepOperator : IOperator
{
    /// <inheritdoc />
    public string Name => "keep";

    /// <inheritdoc />
    public OperatorType Type => OperatorType.Anonymize;

    /// <inheritdoc />
    public string Operate(string text, IReadOnlyDictionary<string, object> parameters) => text;

    /// <inheritdoc />
    public void Validate(IReadOnlyDictionary<string, object> parameters)
    {
    }
}
