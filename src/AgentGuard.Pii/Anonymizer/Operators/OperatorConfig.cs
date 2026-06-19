namespace AgentGuard.Pii.Anonymizer.Operators;

/// <summary>
/// Selects an operator by name and carries its parameters.
/// </summary>
public sealed class OperatorConfig
{
    /// <summary>Initializes a new instance of the <see cref="OperatorConfig"/> class.</summary>
    public OperatorConfig(string operatorName, IReadOnlyDictionary<string, object>? parameters = null)
    {
        OperatorName = operatorName;
        Parameters = parameters ?? new Dictionary<string, object>();
    }

    /// <summary>The operator's name (e.g. <c>replace</c>, <c>mask</c>).</summary>
    public string OperatorName { get; }

    /// <summary>The operator's parameters.</summary>
    public IReadOnlyDictionary<string, object> Parameters { get; }
}
