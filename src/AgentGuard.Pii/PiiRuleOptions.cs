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

    /// <summary>
    /// What to do when a recognizer could not analyze the text - an out-of-process or cloud detector
    /// that is unreachable, times out or rejects the request. Default: <see cref="ErrorBehavior.FailOpen"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Under <see cref="ErrorBehavior.FailOpen"/> and <see cref="ErrorBehavior.Warn"/> the text
    /// continues with whatever the recognizers that did work found redacted, and the result has
    /// <see cref="GuardrailResult.IsError"/> set so the gap is logged, counted and recorded rather than
    /// passing for clean text. Under <see cref="ErrorBehavior.FailClosed"/> the text is blocked.
    /// </para>
    /// <para>
    /// A recognizer that swallows its own failure reports it through
    /// <see cref="PiiRule.ReportRecognizerFailure"/>. One that throws instead leaves nothing to redact
    /// with: the exception becomes a blocking error result under <see cref="ErrorBehavior.FailClosed"/>
    /// and propagates to the caller otherwise.
    /// </para>
    /// </remarks>
    public ErrorBehavior OnError { get; init; } = ErrorBehavior.FailOpen;
}
