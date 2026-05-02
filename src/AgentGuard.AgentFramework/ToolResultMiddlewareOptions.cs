using AgentGuard.Core.Rules.ToolResult;

namespace AgentGuard.AgentFramework;

/// <summary>
/// Configures the function-invocation interception that runs tool-result guardrails
/// against each <c>FunctionResultContent</c> before it is fed back to the LLM.
///
/// When wired (default when a <see cref="ToolResultGuardrailRule"/> is present in the policy
/// and the inner agent has a <c>FunctionInvokingChatClient</c>), each tool result returned
/// by an <c>AIFunction</c> is evaluated by a filtered sub-pipeline. Blocked results are replaced
/// with <see cref="BlockedPlaceholder"/> (or throw a <see cref="Workflows.GuardrailViolationException"/>
/// when <see cref="HardFail"/> is true). Modified (sanitized) results are substituted in place.
/// </summary>
public sealed class ToolResultMiddlewareOptions
{
    /// <summary>
    /// Whether to wire the function-invocation middleware. Default: true.
    /// Set to false to disable interception even when a <see cref="ToolResultGuardrailRule"/> is present.
    /// </summary>
    public bool Enabled { get; init; } = true;

    /// <summary>
    /// Output-phase rule orders to run on each tool result. Defaults include:
    /// PiiRedactionRule (20), SecretsDetectionRule (22), LlmPiiDetectionRule (25), ToolResultGuardrailRule (47).
    /// </summary>
    public ISet<int> IncludeRuleOrders { get; init; } = new HashSet<int>
    {
        20, // PiiRedactionRule
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
    /// When true, throw <see cref="Workflows.GuardrailViolationException"/> on a blocking violation
    /// instead of substituting <see cref="BlockedPlaceholder"/>. Aborts the entire agent run.
    /// Default: false.
    /// </summary>
    public bool HardFail { get; init; }
}
