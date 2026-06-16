namespace AgentGuard.Pii.Anonymizer.Operators;

/// <summary>Whether an operator anonymizes text or reverses a prior anonymization.</summary>
public enum OperatorType
{
    /// <summary>Transforms detected PII (replace, redact, mask, hash, encrypt, keep).</summary>
    Anonymize,

    /// <summary>Reverses a prior transformation (e.g. decrypt).</summary>
    Deanonymize,
}

/// <summary>
/// A transformation applied to a detected PII span.
/// </summary>
public interface IOperator
{
    /// <summary>The operator's unique name (e.g. <c>replace</c>).</summary>
    string Name { get; }

    /// <summary>Whether this operator anonymizes or deanonymizes.</summary>
    OperatorType Type { get; }

    /// <summary>Applies the operator to <paramref name="text"/> using <paramref name="parameters"/>.</summary>
    string Operate(string text, IReadOnlyDictionary<string, object> parameters);

    /// <summary>Validates the parameters; throws <see cref="ArgumentException"/> when invalid.</summary>
    void Validate(IReadOnlyDictionary<string, object> parameters);
}
