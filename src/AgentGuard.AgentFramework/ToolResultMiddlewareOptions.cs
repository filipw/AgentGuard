using AgentGuard.Core.Rules.ToolCall;
using AgentGuard.Core.Rules.ToolResult;

namespace AgentGuard.AgentFramework;

/// <summary>
/// Configures the function-invocation interception that runs tool-call guardrails against each
/// call's arguments before the tool runs, and tool-result guardrails against each
/// <c>FunctionResultContent</c> before it is fed back to the LLM.
///
/// When wired (default when a <see cref="ToolCallGuardrailRule"/> or <see cref="ToolResultGuardrailRule"/>
/// is present in the policy and the inner agent has a <c>FunctionInvokingChatClient</c>), a blocked call
/// is not executed and the model receives <see cref="BlockedToolCallPlaceholder"/> instead; each tool
/// result returned by an <c>AIFunction</c> is evaluated by a filtered sub-pipeline. Blocked results are
/// replaced with <see cref="BlockedPlaceholder"/>, and with <see cref="HardFail"/> a block also stops the
/// run with a <see cref="Workflows.GuardrailViolationException"/>. Modified (sanitized) results are
/// substituted in place.
/// </summary>
public sealed class ToolResultMiddlewareOptions
{
    /// <summary>
    /// Whether to wire the function-invocation middleware. Default: true. Set to false to disable
    /// interception even when a <see cref="ToolCallGuardrailRule"/> or <see cref="ToolResultGuardrailRule"/>
    /// is present.
    /// </summary>
    public bool Enabled { get; init; } = true;

    /// <summary>
    /// Returned to the model in place of the tool's result when a call's arguments violate the policy;
    /// the tool itself is never invoked. Default: a neutral placeholder.
    /// </summary>
    public string BlockedToolCallPlaceholder { get; init; } = "[blocked: tool call violated guardrail policy]";

    /// <summary>
    /// Output-phase rule orders to run on each tool result. Defaults include:
    /// PiiRule (20), SecretsDetectionRule (22), LlmPiiDetectionRule (25), ToolResultGuardrailRule (47).
    /// </summary>
    public ISet<int> IncludeRuleOrders { get; init; } = new HashSet<int>
    {
        20, // PiiRule
        22, // SecretsDetectionRule
        25, // LlmPiiDetectionRule
        47  // ToolResultGuardrailRule
    };

    /// <summary>
    /// Replacement string returned in place of a blocked tool result. The LLM sees this
    /// instead of the poisoned content and can continue the loop. Default: a neutral placeholder.
    /// </summary>
    public string BlockedPlaceholder { get; init; } = "[blocked: tool result violated guardrail policy]";

    /// <summary>
    /// When true, a blocked tool call or tool result stops the whole agent run instead of letting the
    /// model continue. Default: false.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The blocked call is answered with <see cref="BlockedToolCallPlaceholder"/> (the tool never runs)
    /// or its result with <see cref="BlockedPlaceholder"/>, the model is not called again, and once the
    /// inner run has returned <c>RunAsync</c> throws <see cref="Workflows.GuardrailViolationException"/>;
    /// a <c>RunStreamingAsync</c> enumeration throws it after the last update. Calls the model requested
    /// in the same turn that had not run yet are not run either; each is answered with a placeholder, so
    /// the history the agent saves has no call without a result.
    /// </para>
    /// <para>
    /// The run is stopped with <c>FunctionInvocationContext.Terminate</c>, since
    /// <c>FunctionInvokingChatClient</c> turns an exception thrown by a tool into an error result for the
    /// model. The agent must accept <c>ChatClientAgentRunOptions</c> (or no options), as the
    /// function-invocation middleware itself requires.
    /// </para>
    /// </remarks>
    public bool HardFail { get; init; }
}
