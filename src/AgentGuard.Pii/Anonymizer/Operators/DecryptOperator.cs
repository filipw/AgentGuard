namespace AgentGuard.Pii.Anonymizer.Operators;

/// <summary>Reverses <see cref="EncryptOperator"/>, restoring the original PII text.</summary>
public sealed class DecryptOperator : IOperator
{
    /// <inheritdoc />
    public string Name => "decrypt";

    /// <inheritdoc />
    public OperatorType Type => OperatorType.Deanonymize;

    /// <inheritdoc />
    public string Operate(string text, IReadOnlyDictionary<string, object> parameters) =>
        AesCipher.Decrypt(EncryptOperator.GetKey(parameters), text);

    /// <inheritdoc />
    public void Validate(IReadOnlyDictionary<string, object> parameters) =>
        new EncryptOperator().Validate(parameters);
}
