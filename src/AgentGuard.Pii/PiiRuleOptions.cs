using AgentGuard.Core.Abstractions;

namespace AgentGuard.Pii;

/// <summary>
/// Guardrail-side settings for <see cref="PiiRule"/> - the ones that describe how the rule behaves
/// inside a pipeline rather than how the detection engine behaves.
/// </summary>
/// <remarks>
/// These deliberately do not live on the engine's <c>PiiOptions</c>. <c>RedactOutput</c> used to be
/// read from there, which made a guardrail concept (which <see cref="GuardrailPhase"/> the rule
/// registers for) part of an engine that has no notion of phases at all; the engine dropped the
/// property in its next release, which would have been a compile break here.
/// </remarks>
public sealed class PiiRuleOptions
{
    /// <summary>
    /// When true (default), the rule redacts model output as well as input, i.e. it registers for
    /// <see cref="GuardrailPhase.Both"/>. When false it runs on <see cref="GuardrailPhase.Input"/> only.
    /// </summary>
    public bool RedactOutput { get; init; } = true;

    /// <summary>
    /// When true (default), adjacent entities of the same type separated only by spaces are merged
    /// into one span before anonymization. That is what keeps a multi-token name ("John Smith") a
    /// single entity, but it also collapses genuinely separate values - two space-separated email
    /// addresses become one <c>&lt;EMAIL_ADDRESS&gt;</c>. Set to false to anonymize each span on its own.
    /// </summary>
    public bool MergeEntitiesWithSpaces { get; init; } = true;
}
