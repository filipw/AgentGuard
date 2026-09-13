using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Builders;
using AgentGuard.Core.Guardrails;
using AgentGuard.Core.Ledger;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.Logging;

namespace AgentGuard.Core.ChatClient;

/// <summary>
/// Extension methods for wrapping an <see cref="IChatClient"/> with AgentGuard guardrails.
/// </summary>
public static class GuardrailChatClientExtensions
{
    /// <summary>
    /// Wraps this <see cref="IChatClient"/> with AgentGuard guardrails configured via a fluent builder.
    /// Input guardrails run on the last user message; output guardrails run on the response.
    /// Conversation history is automatically propagated from the messages passed to each call.
    /// </summary>
    /// <example>
    /// <code>
    /// var guardedClient = chatClient.UseAgentGuard(g => g
    ///     .UseDefaults()
    ///     .EnforceTopicBoundaryWithLlm(chatClient, "billing", "returns"));
    ///
    /// // Use exactly like a normal IChatClient - guardrails run transparently
    /// var response = await guardedClient.GetResponseAsync(conversationHistory);
    /// </code>
    /// </example>
    /// <param name="client">The client to wrap.</param>
    /// <param name="configure">Configures the policy.</param>
    /// <param name="logger">Optional logger for the pipeline.</param>
    /// <param name="ledger">
    /// Optional decision ledger. The decorator builds its own pipeline, so a ledger registered via
    /// <c>AddAgentGuard(o =&gt; o.UseDecisionLedger(...))</c> only records here if it is passed in.
    /// </param>
    public static IChatClient UseAgentGuard(
        this IChatClient client,
        Action<GuardrailPolicyBuilder> configure,
        ILogger<GuardrailPipeline>? logger = null,
        IGuardrailLedger? ledger = null)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(configure);

        var builder = new GuardrailPolicyBuilder();
        configure(builder);
        // the decorator built this policy, so disposing the client releases its rules
        return new GuardrailChatClient(client, builder.Build(), logger, ledger, ownsPolicy: true);
    }

    /// <summary>
    /// Wraps this <see cref="IChatClient"/> with AgentGuard guardrails using a pre-built policy.
    /// </summary>
    /// <param name="client">The client to wrap.</param>
    /// <param name="policy">The policy to enforce.</param>
    /// <param name="logger">Optional logger for the pipeline.</param>
    /// <param name="ledger">Optional decision ledger; see the builder overload.</param>
    public static IChatClient UseAgentGuard(
        this IChatClient client,
        IGuardrailPolicy policy,
        ILogger<GuardrailPipeline>? logger = null,
        IGuardrailLedger? ledger = null)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(policy);

        return new GuardrailChatClient(client, policy, logger, ledger);
    }
}
