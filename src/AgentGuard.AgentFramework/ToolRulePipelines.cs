using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Guardrails;
using AgentGuard.Core.Ledger;
using AgentGuard.Core.Rules;
using AgentGuard.Core.Rules.ToolCall;
using AgentGuard.Core.Rules.ToolResult;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.Logging;

namespace AgentGuard.AgentFramework;

/// <summary>
/// A policy's tool rules as the sub-pipelines that check tool calls and tool results: the tool-call
/// rules, the text rules (PII, secrets) that rewrite a result, and the tool-result rule that inspects
/// what they produced. Shared by the tool middleware and the Agent-Hooks interceptor, so both check
/// tools the same way.
/// </summary>
internal sealed class ToolRulePipelines
{
    private ToolRulePipelines(GuardrailPipeline? toolCalls, GuardrailPipeline? resultText, GuardrailPipeline? toolResults)
    {
        ToolCalls = toolCalls;
        ResultText = resultText;
        ToolResults = toolResults;
    }

    /// <summary>The tool-call rules, or null when the policy has none.</summary>
    public GuardrailPipeline? ToolCalls { get; }

    /// <summary>The rules that rewrite a tool result's text, or null when results are not inspected.</summary>
    public GuardrailPipeline? ResultText { get; }

    /// <summary>The tool-result rule, or null when the policy has none.</summary>
    public GuardrailPipeline? ToolResults { get; }

    /// <summary>Whether tool results are checked at all.</summary>
    public bool ChecksResults => ResultText is not null || ToolResults is not null;

    /// <summary>Whether <paramref name="policy"/> has anything to check on tool calls or results.</summary>
    public static bool Applies(IGuardrailPolicy policy, ICollection<int> includeRuleOrders)
    {
        var (calls, text, results) = Partition(policy, includeRuleOrders);
        return calls.Count > 0 || text.Count > 0 || results.Count > 0;
    }

    /// <summary>Builds the sub-pipelines for <paramref name="policy"/>.</summary>
    /// <param name="policy">The policy.</param>
    /// <param name="includeRuleOrders">Orders of the output rules that also run on each tool result.</param>
    /// <param name="logger">Logger for the pipelines.</param>
    /// <param name="ledger">Optional decision ledger.</param>
    public static ToolRulePipelines Create(
        IGuardrailPolicy policy,
        ICollection<int> includeRuleOrders,
        ILogger<GuardrailPipeline> logger,
        IGuardrailLedger? ledger)
    {
        var (calls, text, results) = Partition(policy, includeRuleOrders);

        GuardrailPipeline? Build(List<IGuardrailRule> rules, string suffix) =>
            rules.Count == 0
                ? null
                : new GuardrailPipeline(
                    new GuardrailPolicy($"{policy.Name}.{suffix}", rules, policy.ViolationHandler),
                    logger,
                    ledger);

        return new ToolRulePipelines(
            Build(calls, "tool-calls"),
            Build(text, "tool-results.text"),
            Build(results, "tool-results"));
    }

    /// <summary>
    /// Checks tool calls before they run.
    /// </summary>
    /// <returns>The result that blocked them, or null when they may run.</returns>
    public async ValueTask<GuardrailPipelineResult?> CheckCallsAsync(
        IReadOnlyList<AgentToolCall> calls,
        IReadOnlyList<ChatMessage>? messages,
        string? agentName,
        string? stage,
        CancellationToken cancellationToken)
    {
        if (ToolCalls is null || calls.Count == 0)
            return null;

        var context = CreateContext("", messages, agentName, stage);
        context.Properties[ToolCallGuardrailRule.ToolCallsKey] = calls;

        var result = await ToolCalls.RunAsync(context, cancellationToken).ConfigureAwait(false);
        return result.IsBlocked ? result : null;
    }

    /// <summary>
    /// Checks a tool result before it goes back to the model: the text rules rewrite it, then the
    /// tool-result rule inspects what they produced.
    /// </summary>
    /// <param name="toolName">The tool that produced the result.</param>
    /// <param name="content">The result as text.</param>
    /// <param name="messages">The conversation so far, as context for the rules.</param>
    /// <param name="agentName">The agent, when known.</param>
    /// <param name="stage">Where in the host the check runs, recorded on ledger decisions.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async ValueTask<ToolResultCheck> CheckResultAsync(
        string toolName,
        string content,
        IReadOnlyList<ChatMessage>? messages,
        string? agentName,
        string? stage,
        CancellationToken cancellationToken)
    {
        var changed = false;

        // pass 1: text rules rewrite the content in place
        if (ResultText is not null)
        {
            var textResult = await ResultText.RunAsync(CreateContext(content, messages, agentName, stage), cancellationToken).ConfigureAwait(false);
            if (textResult.IsBlocked)
                return ToolResultCheck.Blocked(textResult);

            if (textResult.WasModified)
            {
                content = textResult.FinalText;
                changed = true;
            }
        }

        // pass 2: the tool-result rule sees whatever pass 1 produced
        if (ToolResults is not null)
        {
            var context = CreateContext(content, messages, agentName, stage);
            context.Properties[ToolResultGuardrailRule.ToolResultsKey] =
                (IReadOnlyList<ToolResultEntry>)[new ToolResultEntry { ToolName = toolName, Content = content }];

            var result = await ToolResults.RunAsync(context, cancellationToken).ConfigureAwait(false);
            if (result.IsBlocked)
                return ToolResultCheck.Blocked(result);

            // the rule hands cleaned content back through the property bag, not as FinalText (its
            // text is not the tool result), so WasModified never signals it
            if (context.Properties.TryGetValue(ToolResultGuardrailRule.SanitizedResultsKey, out var sanitizedObj) &&
                sanitizedObj is IReadOnlyList<ToolResultEntry> { Count: > 0 } sanitized &&
                !string.Equals(sanitized[0].Content, content, StringComparison.Ordinal))
            {
                content = sanitized[0].Content;
                changed = true;
            }
        }

        return changed ? ToolResultCheck.Rewritten(content) : ToolResultCheck.Unchanged;
    }

    private static (List<IGuardrailRule> Calls, List<IGuardrailRule> Text, List<IGuardrailRule> Results) Partition(
        IGuardrailPolicy policy, ICollection<int> includeRuleOrders)
    {
        // gated rules (.When/.Unless) are matched by what they wrap but still evaluated through the
        // gate, so their predicate keeps applying
        var calls = policy.Rules.Where(r => r.Unwrap() is ToolCallGuardrailRule).ToList();

        // results are inspected only when the policy has a tool-result rule; the text rules (PII,
        // secrets, LLM PII) then rewrite each result before that rule sees it
        var inspectResults = policy.Rules.Any(r => r.Unwrap() is ToolResultGuardrailRule);
        var included = inspectResults
            ? policy.Rules
                .Where(r => r.Phase.HasFlag(GuardrailPhase.Output) && includeRuleOrders.Contains(r.Order))
                .ToList()
            : [];

        var text = included.Where(r => r.Unwrap() is not (ToolResultGuardrailRule or ToolCallGuardrailRule)).ToList();
        var results = included.Where(r => r.Unwrap() is ToolResultGuardrailRule).ToList();
        return (calls, text, results);
    }

    private static GuardrailContext CreateContext(
        string text, IReadOnlyList<ChatMessage>? messages, string? agentName, string? stage) => new()
        {
            Text = text,
            Phase = GuardrailPhase.Output,
            Messages = messages,
            AgentName = agentName,
            Stage = stage
        };
}

/// <summary>The outcome of checking one tool result.</summary>
/// <param name="Blocking">The result that blocked it, when it was blocked.</param>
/// <param name="Content">The rewritten result, when a rule rewrote it.</param>
internal readonly record struct ToolResultCheck(GuardrailPipelineResult? Blocking, string? Content)
{
    /// <summary>The result passed unchanged.</summary>
    public static ToolResultCheck Unchanged => default;

    /// <summary>The result was blocked.</summary>
    public static ToolResultCheck Blocked(GuardrailPipelineResult result) => new(result, null);

    /// <summary>A rule rewrote the result.</summary>
    public static ToolResultCheck Rewritten(string content) => new(null, content);

    /// <summary>Whether the result was blocked.</summary>
    public bool IsBlocked => Blocking is not null;
}
