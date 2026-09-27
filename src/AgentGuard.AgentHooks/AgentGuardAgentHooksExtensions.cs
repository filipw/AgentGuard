using System.Runtime.CompilerServices;
using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Builders;
using AgentGuard.Core.Guardrails;
using AgentGuard.Core.Ledger;
using AgentHooks;
using Microsoft.Agents.AI;
using Microsoft.Agents.AI.AgentHooks;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace AgentGuard.AgentHooks;

/// <summary>
/// Builds Microsoft Agent Framework agents that enforce an AgentGuard policy through Agent-Hooks
/// (AGENT-HOOKS-0.1): every interception point - input, each model call, each tool call and result, and
/// output - is checked before the run moves on, and the agent's history is written only after the output
/// verdict, so nothing blocked or rewritten away is saved, whatever history provider the agent uses.
/// </summary>
/// <remarks>
/// <para>
/// This is the stricter alternative to <c>UseAgentGuard()</c> on <see cref="AIAgentBuilder"/>, for agents
/// built from a chat client; don't use both on one agent. The agent is created by the Agent Framework's
/// <see cref="AgentHooksChatClientExtensions.AsAIAgentWithAgentHooks(IChatClient, AgentHooksOptions, ChatClientAgentOptions?, IServiceProvider?)"/>,
/// so its rules apply: the chat client must not already contain a function-invocation loop, and per-run
/// chat client factories are rejected.
/// </para>
/// <para>
/// Streaming is buffered: nothing is released before the output verdict. History the model service keeps
/// itself (a conversation id) is saved at the service before any verdict, and tools the service runs
/// itself are only seen after the model call.
/// </para>
/// </remarks>
public static class AgentGuardAgentHooksExtensions
{
    /// <summary>
    /// The <see cref="AgentResponse.AdditionalProperties"/> key under which a violation response carries
    /// the Agent-Hooks <see cref="InterceptionRecord"/> of the blocking verdict.
    /// </summary>
    public const string InterceptionRecordKey = "agentguard.interception";

    // what a violation response says when the blocking verdict carries no message of its own
    private const string DefaultViolationMessage = "The request was blocked by a guardrail policy.";

    /// <summary>
    /// Creates an agent over <paramref name="chatClient"/> that enforces the policy built by
    /// <paramref name="configure"/> at every Agent-Hooks interception point.
    /// </summary>
    /// <param name="chatClient">The chat client the agent talks to, without a function-invocation loop.</param>
    /// <param name="configure">Configures the policy. The policy lives as long as the agent.</param>
    /// <param name="agentOptions">Optional agent options (name, instructions, tools, history provider).</param>
    /// <param name="configureHooks">Optional enforcement settings: tool-call blocking, model-input checks, shadow mode, timeout and so on.</param>
    /// <param name="services">
    /// Optional service provider, passed to the agent. A registered <see cref="IGuardrailLedger"/> and
    /// <see cref="ILoggerFactory"/> are used when the options don't set a ledger or logger.
    /// </param>
    /// <returns>The agent.</returns>
    public static AIAgent AsAIAgentWithAgentGuard(
        this IChatClient chatClient,
        Action<GuardrailPolicyBuilder> configure,
        ChatClientAgentOptions? agentOptions = null,
        Action<AgentGuardHooksOptions>? configureHooks = null,
        IServiceProvider? services = null)
    {
        ArgumentNullException.ThrowIfNull(configure);

        var builder = new GuardrailPolicyBuilder();
        configure(builder);
        return chatClient.AsAIAgentWithAgentGuard(builder.Build(), agentOptions, configureHooks, services);
    }

    /// <summary>
    /// Creates an agent over <paramref name="chatClient"/> that enforces <paramref name="policy"/> at every
    /// Agent-Hooks interception point.
    /// </summary>
    /// <param name="chatClient">The chat client the agent talks to, without a function-invocation loop.</param>
    /// <param name="policy">The policy to enforce. The agent doesn't dispose it.</param>
    /// <param name="agentOptions">Optional agent options (name, instructions, tools, history provider).</param>
    /// <param name="configureHooks">Optional enforcement settings: tool-call blocking, model-input checks, shadow mode, timeout and so on.</param>
    /// <param name="services">
    /// Optional service provider, passed to the agent. A registered <see cref="IGuardrailLedger"/> and
    /// <see cref="ILoggerFactory"/> are used when the options don't set a ledger or logger.
    /// </param>
    /// <returns>The agent.</returns>
    public static AIAgent AsAIAgentWithAgentGuard(
        this IChatClient chatClient,
        IGuardrailPolicy policy,
        ChatClientAgentOptions? agentOptions = null,
        Action<AgentGuardHooksOptions>? configureHooks = null,
        IServiceProvider? services = null)
    {
        ArgumentNullException.ThrowIfNull(chatClient);
        ArgumentNullException.ThrowIfNull(policy);

        var options = new AgentGuardHooksOptions();
        configureHooks?.Invoke(options);

        options.Ledger ??= services?.GetService<IGuardrailLedger>();
        options.Logger ??= services?.GetService<ILoggerFactory>()?.CreateLogger<GuardrailPipeline>();

        var hooks = new AgentHooksOptions()
            .AddInterceptor(new AgentGuardInterceptor(policy, options), "agentguard");

        foreach (var interceptor in options.AdditionalInterceptors)
            hooks.AddInterceptor(interceptor);

        hooks.Mode = options.Mode;
        hooks.Timeout = options.Timeout;
        hooks.Resolver = options.Resolver;
        hooks.Composition = options.Composition;
        hooks.IdentityProvider = options.IdentityProvider;
        hooks.RecordSink = options.RecordSink;

        var agent = chatClient.AsAIAgentWithAgentHooks(hooks, agentOptions, services);

        if (options.ViolationBehavior == ViolationBehavior.Throw)
            return agent;

        // outside the enforcement boundary: a block becomes an ordinary response
        return new AIAgentBuilder(agent)
            .Use(
                runFunc: async (messages, session, runOptions, inner, cancellationToken) =>
                {
                    try
                    {
                        return await inner.RunAsync(messages, session, runOptions, cancellationToken).ConfigureAwait(false);
                    }
                    catch (InterceptionBlockedException blocked) when (IsPolicyDecision(blocked))
                    {
                        return ViolationResponse(blocked, inner);
                    }
                },
                runStreamingFunc: RespondToViolationsWhileStreaming)
            .Build(services);
    }

    private static async IAsyncEnumerable<AgentResponseUpdate> RespondToViolationsWhileStreaming(
        IEnumerable<ChatMessage> messages,
        AgentSession? session,
        AgentRunOptions? runOptions,
        AIAgent inner,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        await using var updates = inner.RunStreamingAsync(messages, session, runOptions, cancellationToken)
            .GetAsyncEnumerator(cancellationToken);

        while (true)
        {
            InterceptionBlockedException? blocked = null;
            try
            {
                if (!await updates.MoveNextAsync().ConfigureAwait(false))
                    yield break;
            }
            catch (InterceptionBlockedException exception) when (IsPolicyDecision(exception))
            {
                blocked = exception;
            }

            if (blocked is not null)
            {
                // the enforcement buffers the stream, so nothing of the blocked run went out before this
                var response = ViolationResponse(blocked, inner);
                yield return new AgentResponseUpdate(ChatRole.Assistant, response.Text)
                {
                    AgentId = inner.Id,
                    AdditionalProperties = response.AdditionalProperties
                };
                yield break;
            }

            yield return updates.Current;
        }
    }

    // a deny the interceptors decided on; errors inside the enforcement (host_error:*) still throw
    private static bool IsPolicyDecision(InterceptionBlockedException blocked) =>
        blocked.Result?.Verdict?.Reason is not { } reason || !reason.StartsWith("host_error:", StringComparison.Ordinal);

    private static AgentResponse ViolationResponse(InterceptionBlockedException blocked, AIAgent agent)
    {
        var message = blocked.Result?.Verdict?.Message is { Length: > 0 } text ? text : DefaultViolationMessage;

        return new AgentResponse(new ChatMessage(ChatRole.Assistant, message))
        {
            AgentId = agent.Id,
            AdditionalProperties = new AdditionalPropertiesDictionary { [InterceptionRecordKey] = blocked.Result }
        };
    }
}
