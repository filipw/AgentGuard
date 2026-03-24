using AgentGuard.Core.Guardrails;
using AgentGuard.Core.Streaming;
using Microsoft.Extensions.AI;

namespace AgentGuard.Core.Abstractions;

public interface IGuardrailPolicy
{
    string Name { get; }
    IReadOnlyList<IGuardrailRule> Rules { get; }
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

public interface IViolationHandler
{
    ValueTask<string> HandleViolationAsync(
        GuardrailResult result,
        GuardrailContext context,
        CancellationToken cancellationToken = default);
}

public interface IAgentGuardFactory
{
    IGuardrailPolicy GetPolicy(string name);
    IGuardrailPolicy GetDefaultPolicy();
}
