using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;

namespace AgentGuard.Pii.Anonymizer.Operators;

/// <summary>
/// AES (CBC mode, PKCS7 padding, random IV) encryption helper, base64url-encoded. The IV is prepended to the ciphertext before encoding.
/// </summary>
public static class AesCipher
{
    /// <summary>Encrypts <paramref name="text"/> with <paramref name="key"/>, returning base64url(iv + ciphertext).</summary>
    public static string Encrypt(byte[] key, string text)
    {
        using var aes = System.Security.Cryptography.Aes.Create();
        aes.Key = key;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        aes.GenerateIV();

        var plaintext = Encoding.UTF8.GetBytes(text);
        using var encryptor = aes.CreateEncryptor();
        var ciphertext = encryptor.TransformFinalBlock(plaintext, 0, plaintext.Length);

        var combined = new byte[aes.IV.Length + ciphertext.Length];
        Buffer.BlockCopy(aes.IV, 0, combined, 0, aes.IV.Length);
        Buffer.BlockCopy(ciphertext, 0, combined, aes.IV.Length, ciphertext.Length);

        return Base64Url.EncodeToString(combined);
    }

    /// <summary>Decrypts a base64url(iv + ciphertext) string produced by <see cref="Encrypt"/>.</summary>
    public static string Decrypt(byte[] key, string text)
    {
        var combined = Base64Url.DecodeFromChars(text);
        var iv = combined[..16];
        var ciphertext = combined[16..];

        using var aes = System.Security.Cryptography.Aes.Create();
        aes.Key = key;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        aes.IV = iv;

        using var decryptor = aes.CreateDecryptor();
        var plaintext = decryptor.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
        return Encoding.UTF8.GetString(plaintext);
    }

    /// <summary>Returns <c>true</c> if the key length is a valid AES key size (128/192/256 bits).</summary>
    public static bool IsValidKeySize(byte[] key) => key.Length is 16 or 24 or 32;
}
