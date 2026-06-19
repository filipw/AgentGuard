using AgentGuard.Core.Builders;

namespace AgentGuard.Pii;

/// <summary>
/// Extension methods for adding PII detection/redaction to the policy builder.
/// </summary>
public static class PiiGuardrailBuilderExtensions
{
    /// <summary>
    /// Adds context-aware PII detection and de-identification (order 20) using the built-in
    /// analyzer and anonymizer. By default detects all supported entities and replaces each with a
    /// <c>&lt;ENTITY_TYPE&gt;</c> tag.
    /// </summary>
    /// <param name="builder">The policy builder.</param>
    /// <param name="options">Optional configuration. When null, defaults are used.</param>
    /// <returns>The builder for chaining.</returns>
    public static GuardrailPolicyBuilder RedactPii(
        this GuardrailPolicyBuilder builder,
        PiiOptions? options = null)
    {
        builder.AddRule(new PiiRule(options));
        return builder;
    }

    /// <summary>
    /// Adds PII detection/redaction (order 20) that replaces every detected entity with a fixed
    /// string (e.g. <c>[REDACTED]</c>).
    /// </summary>
    /// <param name="builder">The policy builder.</param>
    /// <param name="replacement">The replacement string for every detected entity.</param>
    /// <param name="entities">Optional entity types to limit detection to. When empty, all are detected.</param>
    /// <returns>The builder for chaining.</returns>
    public static GuardrailPolicyBuilder RedactPii(
        this GuardrailPolicyBuilder builder,
        string replacement,
        params string[] entities)
    {
        var options = new PiiOptions
        {
            Replacement = replacement,
            Entities = entities is { Length: > 0 } ? entities : null,
        };
        return builder.RedactPii(options);
    }
}
