using System.Numerics;
using System.Security.Cryptography;
using AgentGuard.Pii.Analyzer;

namespace AgentGuard.Pii.Recognizers.Generic;

/// <summary>
/// Recognizes Bitcoin addresses (P2PKH/P2SH via base58 double-SHA256 checksum and Bech32/Bech32m via
/// segwit checksum) using regex plus validation.
/// </summary>
public sealed class CryptoRecognizer : PatternRecognizer
{
    private const string Base58Digits = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    private const string Bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    private const uint Bech32MConst = 0x2BC830A3;

    private static readonly IReadOnlyList<Pattern> DefaultPatterns =
    [
        new Pattern("Crypto (Medium)", @"(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,59}", 0.5),
    ];

    private static readonly IReadOnlyList<string> DefaultContext = ["wallet", "btc", "bitcoin", "crypto"];

    /// <summary>Initializes a new instance of the <see cref="CryptoRecognizer"/> class.</summary>
    public CryptoRecognizer(string supportedEntity = "CRYPTO", string supportedLanguage = "en")
        : base(supportedEntity, patterns: DefaultPatterns, context: DefaultContext, supportedLanguage: supportedLanguage)
    {
    }

    /// <inheritdoc />
    public override bool? ValidateResult(string patternText)
    {
        if (patternText.StartsWith('1') || patternText.StartsWith('3'))
        {
            return ValidateBase58Address(patternText);
        }

        if (patternText.StartsWith("bc1", StringComparison.Ordinal))
        {
            return ValidateBech32Address(patternText);
        }

        return false;
    }

    private static bool ValidateBase58Address(string address)
    {
        try
        {
            var decoded = DecodeBase58(address);
            if (decoded.Length < 4)
            {
                return false;
            }

            var span = decoded.AsSpan();
            var payload = span[..^4];
            var checksum = span[^4..];
            var hash = SHA256.HashData(SHA256.HashData(payload));
            return checksum.SequenceEqual(hash.AsSpan(0, 4));
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static byte[] DecodeBase58(string address)
    {
        var origLen = address.Length;
        var trimmed = address.TrimStart('1');

        BigInteger n = 0;
        foreach (var c in trimmed)
        {
            var index = Base58Digits.IndexOf(c, StringComparison.Ordinal);
            if (index < 0)
            {
                throw new FormatException($"Invalid base58 character '{c}'.");
            }

            n = n * 58 + index;
        }

        // leading '1's map to leading zero bytes
        var leadingZeros = origLen - trimmed.Length;
        var payload = n.IsZero ? [] : n.ToByteArray(isUnsigned: true, isBigEndian: true);
        var result = new byte[leadingZeros + payload.Length];
        Array.Copy(payload, 0, result, leadingZeros, payload.Length);
        return result;
    }

    private static bool ValidateBech32Address(string address)
    {
        var (hrp, data) = Bech32Decode(address);
        return hrp is not null && data is not null;
    }

    private static (string? Hrp, int[]? Data) Bech32Decode(string bech)
    {
        if (bech.Any(c => c < 33 || c > 126))
        {
            return (null, null);
        }

        // reject mixed-case strings (Bech32 must be all-lower or all-upper)
        if (bech.Any(char.IsLower) && bech.Any(char.IsUpper))
        {
            return (null, null);
        }

        bech = bech.ToLowerInvariant();
        var pos = bech.LastIndexOf('1');
        if (pos < 1 || pos + 7 > bech.Length || bech.Length > 90)
        {
            return (null, null);
        }

        var dataPart = bech[(pos + 1)..];
        if (dataPart.Any(c => !Bech32Charset.Contains(c, StringComparison.Ordinal)))
        {
            return (null, null);
        }

        var hrp = bech[..pos];
        var data = dataPart.Select(c => Bech32Charset.IndexOf(c, StringComparison.Ordinal)).ToArray();
        var spec = Bech32VerifyChecksum(hrp, data);
        if (spec is null)
        {
            return (null, null);
        }

        return (hrp, data[..^6]);
    }

    private static int? Bech32VerifyChecksum(string hrp, int[] data)
    {
        var values = Bech32HrpExpand(hrp).Concat(data).ToArray();
        var poly = Bech32Polymod(values);
        return poly switch
        {
            1 => 1,
            Bech32MConst => 2,
            _ => null,
        };
    }

    private static uint Bech32Polymod(IReadOnlyList<int> values)
    {
        uint[] generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3];
        uint chk = 1;
        foreach (var value in values)
        {
            var top = chk >> 25;
            chk = ((chk & 0x1FFFFFF) << 5) ^ (uint)value;
            for (var i = 0; i < 5; i++)
            {
                chk ^= ((top >> i) & 1) != 0 ? generator[i] : 0;
            }
        }

        return chk;
    }

    private static int[] Bech32HrpExpand(string hrp)
    {
        var high = hrp.Select(c => c >> 5);
        var low = hrp.Select(c => c & 31);
        return high.Append(0).Concat(low).ToArray();
    }
}
