using AgentGuard.Core.Abstractions;

namespace AgentGuard.Pii;

/// <summary>
/// Guardrail-side settings for <see cref="PiiRule"/> - the ones that describe how the rule behaves
/// inside a pipeline rather than how the detection engine behaves.
/// </summary>
/// <remarks>
/// This deliberately does not live on the engine's <c>PiiOptions</c>: which
/// <see cref="GuardrailPhase"/> the rule registers for is a guardrail concept, and the engine has no
/// notion of phases. Settings that genuinely belong to detection or anonymization - including
/// <c>MergeEntitiesWithSpaces</c> - stay on <c>PiiOptions</c> where the engine owns them.
/// </remarks>
public sealed class PiiRuleOptions
{
    /// <summary>
    /// When true (default), the rule redacts model output as well as input, i.e. it registers for
    /// <see cref="GuardrailPhase.Both"/>. When false it runs on <see cref="GuardrailPhase.Input"/> only.
    /// </summary>
    public bool RedactOutput { get; init; } = true;

}
