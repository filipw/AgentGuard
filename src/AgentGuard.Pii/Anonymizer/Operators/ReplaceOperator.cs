namespace AgentGuard.Pii.Anonymizer.Operators;

/// <summary>Replaces a PII span with a fixed value, defaulting to <c>&lt;ENTITY_TYPE&gt;</c>.</summary>
public sealed class ReplaceOperator : IOperator
{
    /// <inheritdoc />
    public string Name => "replace";

    /// <inheritdoc />
    public OperatorType Type => OperatorType.Anonymize;

    /// <inheritdoc />
    public string Operate(string text, IReadOnlyDictionary<string, object> parameters)
    {
        var newValue = OperatorParams.Get<string>(parameters, OperatorParams.NewValue);
        if (string.IsNullOrEmpty(newValue))
        {
            var entityType = OperatorParams.Get<string>(parameters, OperatorParams.EntityType, "");
            return $"<{entityType}>";
        }

        return newValue;
    }

    /// <inheritdoc />
    public void Validate(IReadOnlyDictionary<string, object> parameters)
    {
        if (parameters.TryGetValue(OperatorParams.NewValue, out var value) && value is not string)
        {
            throw new ArgumentException($"Invalid parameter: '{OperatorParams.NewValue}' must be a string.");
        }
    }
}
