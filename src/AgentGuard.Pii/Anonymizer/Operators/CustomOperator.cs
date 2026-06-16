namespace AgentGuard.Pii.Anonymizer.Operators;

/// <summary>
/// Applies a user-supplied function to a PII span. The function is passed via the <c>lambda</c>
/// parameter as a <see cref="Func{String, String}"/>.
/// </summary>
public sealed class CustomOperator : IOperator
{
    /// <summary>Parameter key holding the transformation function.</summary>
    public const string Lambda = "lambda";

    /// <inheritdoc />
    public string Name => "custom";

    /// <inheritdoc />
    public OperatorType Type => OperatorType.Anonymize;

    /// <inheritdoc />
    public string Operate(string text, IReadOnlyDictionary<string, object> parameters)
    {
        var fn = OperatorParams.Get<Func<string, string>>(parameters, Lambda)
                 ?? throw new ArgumentException($"Invalid parameter: '{Lambda}' is required.");
        return fn(text);
    }

    /// <inheritdoc />
    public void Validate(IReadOnlyDictionary<string, object> parameters)
    {
        if (!parameters.TryGetValue(Lambda, out var value) || value is not Func<string, string>)
        {
            throw new ArgumentException($"Invalid parameter: '{Lambda}' must be a Func<string, string>.");
        }
    }
}
