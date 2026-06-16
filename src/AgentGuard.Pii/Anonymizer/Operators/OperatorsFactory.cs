namespace AgentGuard.Pii.Anonymizer.Operators;

/// <summary>
/// Resolves <see cref="IOperator"/> instances by name and type.
/// </summary>
public sealed class OperatorsFactory
{
    private readonly Dictionary<string, IOperator> _anonymizers;
    private readonly Dictionary<string, IOperator> _deanonymizers;

    /// <summary>Initializes a new instance of the <see cref="OperatorsFactory"/> class with the built-in operators.</summary>
    public OperatorsFactory()
    {
        IOperator[] builtIn =
        [
            new ReplaceOperator(),
            new RedactOperator(),
            new KeepOperator(),
            new MaskOperator(),
            new HashOperator(),
            new EncryptOperator(),
            new CustomOperator(),
            new DecryptOperator(),
        ];

        _anonymizers = builtIn.Where(o => o.Type == OperatorType.Anonymize).ToDictionary(o => o.Name);
        _deanonymizers = builtIn.Where(o => o.Type == OperatorType.Deanonymize).ToDictionary(o => o.Name);
    }

    /// <summary>Registers or replaces an operator.</summary>
    public void AddOperator(IOperator op)
    {
        var target = op.Type == OperatorType.Anonymize ? _anonymizers : _deanonymizers;
        target[op.Name] = op;
    }

    /// <summary>Returns the operator with the given name for the given type.</summary>
    public IOperator Create(string operatorName, OperatorType type)
    {
        var source = type == OperatorType.Anonymize ? _anonymizers : _deanonymizers;
        if (source.TryGetValue(operatorName, out var op))
        {
            return op;
        }

        throw new ArgumentException($"Invalid operator '{operatorName}' for type '{type}'.");
    }

    /// <summary>Returns the names of all anonymize operators.</summary>
    public IReadOnlyCollection<string> GetAnonymizers() => _anonymizers.Keys;
}
