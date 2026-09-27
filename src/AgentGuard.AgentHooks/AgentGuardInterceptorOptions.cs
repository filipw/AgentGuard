using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Guardrails;
using AgentGuard.Core.Ledger;
using AgentHooks;
using Microsoft.Extensions.Logging;

namespace AgentGuard.AgentHooks;

/// <summary>
/// Where the tool-call rules check a tool call the host runs, and what a block does to the run. Tools the
/// model service runs itself are checked at <c>post_model_call</c> either way, and a block there ends the run.
/// </summary>
public enum ToolCallBlocking
{
    /// <summary>
    /// Each call is checked at <c>pre_tool_call</c>, just before it runs. A blocked call never runs,
    /// the model receives <see cref="AgentGuardInterceptorOptions.BlockedToolCallMessage"/> as the
    /// call's error, and the agent loop continues.
    /// </summary>
    ContinueWithToolError = 0,

    /// <summary>
    /// The tool calls a model response asks for are checked at <c>post_model_call</c>, before any of
    /// them runs. A block ends the run.
    /// </summary>
    StopRun = 1
}

/// <summary>Options for <see cref="AgentGuardInterceptor"/>.</summary>
public class AgentGuardInterceptorOptions
{
    /// <summary>Logger for the guardrail pipelines. Null logs nothing.</summary>
    public ILogger<GuardrailPipeline>? Logger { get; set; }

    /// <summary>
    /// Optional decision ledger. Every evaluation is recorded, with the interception point as the
    /// decision's <see cref="GuardrailDecision.Stage"/>.
    /// </summary>
    public IGuardrailLedger? Ledger { get; set; }

    /// <summary>
    /// Whether to check the whole request before each model call (<c>pre_model_call</c>): the user and
    /// system messages the caller didn't send - history loaded from a store, messages a context provider
    /// such as a retriever added - go through the input rules. Each distinct text is judged once; a
    /// blocked message is replaced with <see cref="ChatMessageGuard.RemovedMessagePlaceholder"/> and the
    /// call goes ahead. Default: false.
    /// </summary>
    public bool GuardModelInput { get; set; }

    /// <summary>
    /// Where tool calls are checked. Default: <see cref="ToolCallBlocking.ContinueWithToolError"/>.
    /// </summary>
    public ToolCallBlocking ToolCallBlocking { get; set; } = ToolCallBlocking.ContinueWithToolError;

    /// <summary>
    /// Orders of the output rules that also run on each tool result, when the policy has a
    /// <c>GuardToolResults()</c> rule: by default PII (20), secrets (22), LLM PII (25) and the
    /// tool-result rule itself (47). The text rules rewrite the result first, then the tool-result rule
    /// inspects what they produced.
    /// </summary>
    public ISet<int> ToolResultRuleOrders { get; } = new HashSet<int> { 20, 22, 25, 47 };

    /// <summary>
    /// The error the model receives for a blocked tool call. Default: a neutral placeholder that doesn't
    /// tell the model which check fired.
    /// </summary>
    public string BlockedToolCallMessage { get; set; } = "[blocked: tool call violated guardrail policy]";

    /// <summary>The error the model receives in place of a blocked tool result. Default: a neutral placeholder.</summary>
    public string BlockedToolResultMessage { get; set; } = "[blocked: tool result violated guardrail policy]";

    /// <summary>
    /// Decides which blocks become an escalation - a deny that an Agent-Hooks approval resolver
    /// (<see cref="IApprovalResolver"/>) can lift - instead of a plain deny. Null (the default) never
    /// escalates.
    /// </summary>
    public Func<GuardrailResult, InterceptionPoint, bool>? EscalateWhen { get; set; }
}
