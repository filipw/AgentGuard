using System.Security.Cryptography;

namespace AgentGuard.Pii.Anonymizer.Operators;

/// <summary>Reverses <see cref="EncryptOperator"/>, restoring the original PII text.</summary>
public sealed class DecryptOperator : IOperator
{
    /// <inheritdoc />
    public string Name => "decrypt";

    /// <inheritdoc />
    public OperatorType Type => OperatorType.Deanonymize;

    /// <inheritdoc />
    public string Operate(string text, IReadOnlyDictionary<string, object> parameters)
    {
        try
        {
            return AesCipher.Decrypt(EncryptOperator.GetKey(parameters), text);
        }
        catch (CryptographicException ex)
        {
            // a wrong key produces a padding/block failure; surface it rather than returning ciphertext.
            throw new InvalidOperationException(
                "Decryption failed: the key is incorrect or the value is not a valid ciphertext.", ex);
        }
        catch (Exception ex) when (ex is FormatException or ArgumentOutOfRangeException)
        {
            // FormatException: not base64url. ArgumentOutOfRangeException: decoded too short to hold
            // the 16-byte IV (truncated/corrupted ciphertext). Either way it is not a valid ciphertext.
            throw new InvalidOperationException(
                "Decryption failed: the value is not a valid base64url ciphertext.", ex);
        }
    }

    /// <inheritdoc />
    public void Validate(IReadOnlyDictionary<string, object> parameters) =>
        new EncryptOperator().Validate(parameters);
}
