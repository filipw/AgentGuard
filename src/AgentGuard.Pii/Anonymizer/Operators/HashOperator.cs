using System.Security.Cryptography;
using System.Text;

namespace AgentGuard.Pii.Anonymizer.Operators;

/// <summary>
/// Replaces a PII span with a salted SHA-256/512 hash.
/// </summary>
public sealed class HashOperator : IOperator
{
    private const string Sha256Type = "sha256";
    private const string Sha512Type = "sha512";

    /// <inheritdoc />
    public string Name => "hash";

    /// <inheritdoc />
    public OperatorType Type => OperatorType.Anonymize;

    /// <inheritdoc />
    public string Operate(string text, IReadOnlyDictionary<string, object> parameters)
    {
        var hashType = GetHashTypeOrDefault(parameters);
        var salt = GetSalt(parameters);

        var textBytes = Encoding.UTF8.GetBytes(text);
        var salted = new byte[textBytes.Length + salt.Length];
        Buffer.BlockCopy(textBytes, 0, salted, 0, textBytes.Length);
        Buffer.BlockCopy(salt, 0, salted, textBytes.Length, salt.Length);

        var digest = hashType == Sha512Type ? SHA512.HashData(salted) : SHA256.HashData(salted);
        return Convert.ToHexStringLower(digest);
    }

    /// <inheritdoc />
    public void Validate(IReadOnlyDictionary<string, object> parameters)
    {
        var hashType = GetHashTypeOrDefault(parameters);
        if (hashType is not (Sha256Type or Sha512Type))
        {
            throw new ArgumentException($"Invalid parameter: '{OperatorParams.HashType}' must be '{Sha256Type}' or '{Sha512Type}'.");
        }

        if (parameters.TryGetValue(OperatorParams.Salt, out var saltValue))
        {
            var salt = NormalizeSalt(saltValue);
            if (salt.Length is 0 or < 16)
            {
                throw new ArgumentException("Salt must be at least 16 bytes (128 bits), or omitted to auto-generate.");
            }
        }
    }

    private static string GetHashTypeOrDefault(IReadOnlyDictionary<string, object> parameters) =>
        OperatorParams.Get<string>(parameters, OperatorParams.HashType, Sha256Type)!;

    private static byte[] GetSalt(IReadOnlyDictionary<string, object> parameters)
    {
        if (parameters.TryGetValue(OperatorParams.Salt, out var saltValue))
        {
            return NormalizeSalt(saltValue);
        }

        return RandomNumberGenerator.GetBytes(32);
    }

    private static byte[] NormalizeSalt(object saltValue) => saltValue switch
    {
        byte[] bytes => bytes,
        string s => Encoding.UTF8.GetBytes(s),
        _ => throw new ArgumentException($"Invalid parameter: '{OperatorParams.Salt}' must be a string or byte array."),
    };
}
