using AgentGuard.Core.Ledger;
using Microsoft.Extensions.Logging;

namespace AgentGuard.AgentFramework.Workflows;

/// <summary>
/// Options for configuring a <see cref="GuardedExecutor{TInput}"/> or <see cref="GuardedExecutor{TInput, TOutput}"/>.
/// </summary>
public sealed class GuardedExecutorOptions
{
    /// <summary>
    /// Custom text extractor for converting typed messages to strings for guardrail evaluation, and for
    /// rebuilding message types the executor can't rebuild itself when a rule rewrites their text
    /// (<see cref="ITextExtractor.TryRebuild"/>). It is not consulted for chat payloads (<c>ChatMessage</c>,
    /// chat message collections, <c>AgentResponse</c>), which the executor guards message by message.
    /// If null, <see cref="DefaultTextExtractor.Instance"/> is used.
    /// </summary>
    public ITextExtractor? TextExtractor { get; set; }

    /// <summary>
    /// Logger for the guardrail pipeline. If null, a null logger is used.
    /// </summary>
    public ILogger? Logger { get; set; }

    /// <summary>
    /// Optional decision ledger. The executor builds its own <see cref="Core.Guardrails.GuardrailPipeline"/>,
    /// so a ledger registered with <c>AddAgentGuard</c> only records here if it is supplied.
    /// </summary>
    public IGuardrailLedger? Ledger { get; set; }
}
