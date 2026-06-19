namespace AgentGuard.Pii.Anonymizer.Operators;

/// <summary>Well-known parameter keys shared across operators.</summary>
public static class OperatorParams
{
    /// <summary>The entity type of the span being operated on (injected by the engine).</summary>
    public const string EntityType = "entity_type";

    /// <summary>Replacement text for the <c>replace</c> operator.</summary>
    public const string NewValue = "new_value";

    /// <summary>Masking character for the <c>mask</c> operator.</summary>
    public const string MaskingChar = "masking_char";

    /// <summary>Number of characters to mask for the <c>mask</c> operator.</summary>
    public const string CharsToMask = "chars_to_mask";

    /// <summary>Whether the <c>mask</c> operator masks from the end of the value.</summary>
    public const string FromEnd = "from_end";

    /// <summary>Hash algorithm for the <c>hash</c> operator (<c>sha256</c> or <c>sha512</c>).</summary>
    public const string HashType = "hash_type";

    /// <summary>Optional salt for the <c>hash</c> operator.</summary>
    public const string Salt = "salt";

    /// <summary>Encryption key for the <c>encrypt</c>/<c>decrypt</c> operators.</summary>
    public const string Key = "key";

    /// <summary>Helper to read a typed parameter, returning <paramref name="fallback"/> when absent.</summary>
    public static T? Get<T>(IReadOnlyDictionary<string, object> parameters, string key, T? fallback = default)
    {
        if (parameters.TryGetValue(key, out var value) && value is T typed)
        {
            return typed;
        }

        return fallback;
    }
}
