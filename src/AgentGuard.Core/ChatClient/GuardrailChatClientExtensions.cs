using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Builders;
using AgentGuard.Core.Guardrails;
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
    public static IChatClient UseAgentGuard(
        this IChatClient client,
        Action<GuardrailPolicyBuilder> configure,
        ILogger<GuardrailPipeline>? logger = null)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(configure);

        var builder = new GuardrailPolicyBuilder();
        configure(builder);
        return new GuardrailChatClient(client, builder.Build(), logger);
    }

    /// <summary>
    /// Wraps this <see cref="IChatClient"/> with AgentGuard guardrails using a pre-built policy.
    /// </summary>
    public static IChatClient UseAgentGuard(
        this IChatClient client,
        IGuardrailPolicy policy,
        ILogger<GuardrailPipeline>? logger = null)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(policy);

        return new GuardrailChatClient(client, policy, logger);
    }
}
