using AgentGuard.Core.Guardrails;
using AgentGuard.Core.Streaming;
using Microsoft.Extensions.AI;

namespace AgentGuard.Core.Abstractions;

/// <summary>
/// A named, ordered set of rules plus the handler that turns a violation into a user-facing message.
/// </summary>
public interface IGuardrailPolicy
{
    /// <summary>The policy name. Reported on spans, metrics and ledger entries.</summary>
    string Name { get; }

    /// <summary>The rules, in ascending <see cref="IGuardrailRule.Order"/>.</summary>
    IReadOnlyList<IGuardrailRule> Rules { get; }

    /// <summary>Produces the replacement text shown when a rule blocks.</summary>
    IViolationHandler ViolationHandler { get; }

    /// <summary>
    /// Progressive streaming options, if progressive streaming is enabled for this policy.
    /// When null, streaming uses the default buffer-then-release strategy.
    /// </summary>
    ProgressiveStreamingOptions? ProgressiveStreaming => null;

    /// <summary>
    /// Re-ask options, if re-ask (self-healing) is enabled for this policy.
    /// When non-null, the pipeline will re-prompt the LLM on output guardrail violations.
    /// </summary>
    ReaskOptions? ReaskOptions => null;

    /// <summary>
    /// The <see cref="IChatClient"/> used for re-ask calls when <see cref="ReaskOptions"/> is enabled.
    /// </summary>
    IChatClient? ReaskChatClient => null;
}

/// <summary>Turns a blocked result into the text the caller sees instead.</summary>
public interface IViolationHandler
{
    /// <summary>Produces the replacement text for a blocked evaluation.</summary>
    /// <param name="result">The blocking result.</param>
    /// <param name="context">The context that was evaluated.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    ValueTask<string> HandleViolationAsync(
        GuardrailResult result,
        GuardrailContext context,
        CancellationToken cancellationToken = default);
}

/// <summary>Resolves the policies registered with <c>AddAgentGuard</c>.</summary>
public interface IAgentGuardFactory
{
    /// <summary>Gets a named policy.</summary>
    /// <param name="name">The policy name.</param>
    /// <exception cref="InvalidOperationException">No policy with that name is registered.</exception>
    IGuardrailPolicy GetPolicy(string name);

    /// <summary>Gets the default policy, which is empty when none was configured.</summary>
    IGuardrailPolicy GetDefaultPolicy();
}
