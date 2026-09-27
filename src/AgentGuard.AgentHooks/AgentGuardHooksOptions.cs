using AgentGuard.Core.Abstractions;
using AgentHooks;
using Microsoft.Agents.AI;
using Microsoft.Agents.AI.AgentHooks;
using Microsoft.Extensions.AI;

namespace AgentGuard.AgentHooks;

/// <summary>What the caller of an agent sees when a run is blocked.</summary>
public enum ViolationBehavior
{
    /// <summary>
    /// The run returns the blocking verdict's message as an ordinary assistant response - for AgentGuard's
    /// own blocks, the policy's violation message. Errors inside the enforcement still throw.
    /// </summary>
    Respond = 0,

    /// <summary>The run throws <see cref="InterceptionBlockedException"/>, as Agent-Hooks does on its own.</summary>
    Throw = 1
}

/// <summary>
/// Options for the agents built by
/// <see cref="AgentGuardAgentHooksExtensions.AsAIAgentWithAgentGuard(IChatClient, IGuardrailPolicy, ChatClientAgentOptions?, Action{AgentGuardHooksOptions}?, IServiceProvider?)"/>:
/// the interceptor's options plus the Agent-Hooks enforcement settings (<see cref="AgentHooksOptions"/>).
/// </summary>
public sealed class AgentGuardHooksOptions : AgentGuardInterceptorOptions
{
    /// <summary>
    /// Whether verdicts are enforced (the default) or only recorded, which lets a policy run in shadow
    /// mode before it is enforced.
    /// </summary>
    public EnforcementMode Mode { get; set; } = EnforcementMode.Enforce;

    /// <summary>
    /// How long one interceptor may take at one interception point. A timeout is a deny, so it has to
    /// cover the slowest rule - an LLM judge can take several seconds. Default: 30 seconds; null uses
    /// the Agent-Hooks default of 5 seconds.
    /// </summary>
    public TimeSpan? Timeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>Optional approval resolver, consulted for escalations (see <see cref="AgentGuardInterceptorOptions.EscalateWhen"/>).</summary>
    public IApprovalResolver? Resolver { get; set; }

    /// <summary>How the verdicts of several interceptors combine; null uses the Agent-Hooks default (sequential, first deny wins).</summary>
    public CompositionConfig? Composition { get; set; }

    /// <summary>How interception records identify the content they cover; null uses the Agent-Hooks default.</summary>
    public IdentityProvider? IdentityProvider { get; set; }

    /// <summary>Optional callback receiving every Agent-Hooks interception record.</summary>
    public Action<InterceptionRecord>? RecordSink { get; set; }

    /// <summary>Other interceptors to enforce alongside AgentGuard's, in order, after it.</summary>
    public IList<IInterceptor> AdditionalInterceptors { get; } = [];

    /// <summary>What the caller sees when a run is blocked. Default: <see cref="ViolationBehavior.Respond"/>.</summary>
    public ViolationBehavior ViolationBehavior { get; set; } = ViolationBehavior.Respond;
}
