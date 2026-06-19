using System.Text;

namespace AgentGuard.Pii.Anonymizer.Operators;

/// <summary>Encrypts a PII span with AES so it can later be restored via <see cref="DecryptOperator"/>.</summary>
public sealed class EncryptOperator : IOperator
{
    /// <inheritdoc />
    public string Name => "encrypt";

    /// <inheritdoc />
    public OperatorType Type => OperatorType.Anonymize;

    /// <inheritdoc />
    public string Operate(string text, IReadOnlyDictionary<string, object> parameters) =>
        AesCipher.Encrypt(GetKey(parameters), text);

    /// <inheritdoc />
    public void Validate(IReadOnlyDictionary<string, object> parameters)
    {
        if (!parameters.TryGetValue(OperatorParams.Key, out var keyValue))
        {
            throw new ArgumentException($"Invalid parameter: '{OperatorParams.Key}' is required.");
        }

        if (!AesCipher.IsValidKeySize(ToKeyBytes(keyValue)))
        {
            throw new ArgumentException($"Invalid input, '{OperatorParams.Key}' must be of length 128, 192 or 256 bits.");
        }
    }

    internal static byte[] GetKey(IReadOnlyDictionary<string, object> parameters) =>
        parameters.TryGetValue(OperatorParams.Key, out var keyValue)
            ? ToKeyBytes(keyValue)
            : throw new ArgumentException($"Invalid parameter: '{OperatorParams.Key}' is required.");

    private static byte[] ToKeyBytes(object keyValue) => keyValue switch
    {
        byte[] bytes => bytes,
        string s => Encoding.UTF8.GetBytes(s),
        _ => throw new ArgumentException($"Invalid parameter: '{OperatorParams.Key}' must be a string or byte array."),
    };
}
