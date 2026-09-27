using AgentGuard.Core.Guardrails;
using Microsoft.Extensions.AI;

namespace AgentGuard.Core.Abstractions;

/// <summary>Which side of an agent turn a rule inspects.</summary>
[Flags]
public enum GuardrailPhase
{
    /// <summary>The text going into the model.</summary>
    Input = 1,

    /// <summary>The text coming out of the model.</summary>
    Output = 2,

    /// <summary>Both directions.</summary>
    Both = Input | Output
}

/// <summary>The verdict a single rule reached about one piece of text.</summary>
public sealed record GuardrailResult
{
    /// <summary>Whether the rule rejected the text. A blocked result short-circuits the pipeline.</summary>
    public bool IsBlocked { get; init; }

    /// <summary>Whether the rule rewrote the text; the replacement is in <see cref="ModifiedText"/>.</summary>
    public bool IsModified { get; init; }

    /// <summary>Human-readable explanation of a block or a modification.</summary>
    public string? Reason { get; init; }

    /// <summary>The rewritten text, when <see cref="IsModified"/> is true.</summary>
    public string? ModifiedText { get; init; }

    /// <summary>The rule that produced this result. Stamped by the pipeline.</summary>
    public string RuleName { get; init; } = "";

    /// <summary>How serious the block is. <see cref="GuardrailSeverity.None"/> when nothing was blocked.</summary>
    public GuardrailSeverity Severity { get; init; } = GuardrailSeverity.None;

    /// <summary>Rule-specific detail - classifier scores, matched categories, violation counts.</summary>
    public IReadOnlyDictionary<string, object>? Metadata { get; init; }

    /// <summary>
    /// True when the rule encountered an error (e.g. API timeout, model unavailable)
    /// and returned a default result rather than an actual classification.
    /// Check this to distinguish "checked and clean" from "failed to check".
    /// </summary>
    public bool IsError { get; init; }

    /// <summary>
    /// True when the text was let through but the rule wants the outcome surfaced rather than
    /// recorded quietly. <see cref="Error"/> sets it for <see cref="ErrorBehavior.Warn"/>. The
    /// pipeline logs such a result at Warning level and lists it in
    /// <see cref="GuardrailPipelineResult.Warnings"/>.
    /// </summary>
    public bool IsWarning { get; init; }

    /// <summary>The text was checked and is acceptable.</summary>
    public static GuardrailResult Passed() => new() { IsBlocked = false };

    /// <summary>The text was checked and must not proceed.</summary>
    /// <param name="reason">Why it was blocked.</param>
    /// <param name="severity">How serious the violation is.</param>
    public static GuardrailResult Blocked(string reason, GuardrailSeverity severity = GuardrailSeverity.High) =>
        new() { IsBlocked = true, Reason = reason, Severity = severity };

    /// <summary>The text was rewritten and the rewritten form should continue through the pipeline.</summary>
    /// <param name="modifiedText">The replacement text.</param>
    /// <param name="reason">What was changed and why.</param>
    public static GuardrailResult Modified(string modifiedText, string reason) =>
        new() { IsModified = true, ModifiedText = modifiedText, Reason = reason };

    /// <summary>
    /// Creates the result for a rule that could not reach a verdict, shaped by <paramref name="behavior"/>.
    /// Every error result has <see cref="IsError"/> set and carries <c>error</c> (plus
    /// <c>errorDetail</c> when a detail is given) in <see cref="Metadata"/>:
    /// <see cref="ErrorBehavior.FailOpen"/> passes with no <see cref="Reason"/>,
    /// <see cref="ErrorBehavior.Warn"/> passes with a <see cref="Reason"/> and <see cref="IsWarning"/> set,
    /// and <see cref="ErrorBehavior.FailClosed"/> blocks with <see cref="GuardrailSeverity.High"/>.
    /// </summary>
    /// <param name="ruleName">The rule's name, used in the reason.</param>
    /// <param name="behavior">How the error is handled.</param>
    /// <param name="detail">What went wrong, recorded as <c>errorDetail</c> metadata.</param>
    public static GuardrailResult Error(string ruleName, ErrorBehavior behavior, string? detail = null)
    {
        var metadata = new Dictionary<string, object> { ["error"] = true };
        if (detail is not null)
            metadata["errorDetail"] = detail;

        return behavior switch
        {
            ErrorBehavior.FailClosed => new GuardrailResult
            {
                IsBlocked = true,
                IsError = true,
                Reason = $"{ruleName} encountered an error and ErrorBehavior is FailClosed",
                Severity = GuardrailSeverity.High,
                Metadata = metadata
            },
            ErrorBehavior.Warn => new GuardrailResult
            {
                IsBlocked = false,
                IsError = true,
                IsWarning = true,
                Reason = $"{ruleName} encountered an error and ErrorBehavior is Warn; the text passed without this check",
                Metadata = metadata
            },
            _ => new GuardrailResult
            {
                IsBlocked = false,
                IsError = true,
                Metadata = metadata
            }
        };
    }
}

/// <summary>
/// Configures what happens when a guardrail rule encounters an error
/// (e.g. API timeout, model unavailable, HTTP failure). Under every behavior the result has
/// <see cref="GuardrailResult.IsError"/> set and error metadata attached, so telemetry and the
/// decision ledger record the failure.
/// </summary>
public enum ErrorBehavior
{
    /// <summary>
    /// Pass the text through quietly (fail-open): the result carries no reason and the pipeline logs
    /// the error at Debug level. Default for most rules.
    /// </summary>
    FailOpen = 0,
    /// <summary>
    /// Pass the text through but surface the error: the result carries a reason and has
    /// <see cref="GuardrailResult.IsWarning"/> set, the pipeline logs it at Warning level, and
    /// <see cref="GuardrailPipelineResult.Warnings"/> lists it.
    /// </summary>
    Warn = 1,
    /// <summary>Block the text (fail-closed). Use when safety is more important than availability.</summary>
    FailClosed = 2
}

/// <summary>How serious a blocked result is. Reported on spans and the block metric.</summary>
public enum GuardrailSeverity
{
    /// <summary>Nothing was blocked.</summary>
    None = 0,

    /// <summary>Minor - worth recording, rarely worth acting on.</summary>
    Low = 1,

    /// <summary>Notable policy violation.</summary>
    Medium = 2,

    /// <summary>Serious violation.</summary>
    High = 3,

    /// <summary>Active attack or credential exposure.</summary>
    Critical = 4
}

/// <summary>
/// Everything a rule is given about the text it is evaluating.
/// </summary>
/// <remarks>
/// <see cref="Properties"/> is shared by reference across the pipeline's per-rule copies of this
/// record, which is how the property-bag rules (retrieval, tool call, tool result) hand structured
/// input and output to each other and back to the caller.
/// </remarks>
public sealed record GuardrailContext
{
    /// <summary>The text being evaluated, as rewritten by any earlier rule in the pipeline.</summary>
    public required string Text { get; init; }

    /// <summary>Which phase this evaluation belongs to.</summary>
    public required GuardrailPhase Phase { get; init; }

    /// <summary>The conversation so far, when the caller supplied it. Used by the LLM judge rules.</summary>
    public IReadOnlyList<ChatMessage>? Messages { get; init; }

    /// <summary>The agent this evaluation belongs to, when known. Recorded on spans and ledger entries.</summary>
    public string? AgentName { get; init; }

    /// <summary>
    /// Where in the host this evaluation happens, for example an Agent-Hooks interception point such as
    /// <c>input</c> or <c>pre_tool_call</c>. Recorded on ledger decisions; null when the host doesn't
    /// say.
    /// </summary>
    public string? Stage { get; init; }

    /// <summary>
    /// Structured side-channel shared by every rule in a run. Well-known keys are declared as
    /// constants on the rules that use them.
    /// </summary>
    public IDictionary<string, object> Properties { get; init; } = new Dictionary<string, object>();
}

/// <summary>One guardrail check. Implement this to add a rule of your own.</summary>
public interface IGuardrailRule
{
    /// <summary>Stable identifier, used in logs, spans, metrics and ledger entries.</summary>
    string Name { get; }

    /// <summary>Which phases this rule runs in.</summary>
    GuardrailPhase Phase { get; }

    /// <summary>
    /// Execution order within a phase, ascending. The built-in rules occupy 5 to 76; see the rules
    /// reference for the map. Defaults to 100, i.e. after all of them.
    /// </summary>
    int Order => 100;

    /// <summary>Evaluates the text in <paramref name="context"/>.</summary>
    /// <param name="context">The text and its surrounding state.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The verdict. Rules that call out of process should return
    /// <see cref="GuardrailResult.Error"/> rather than throwing.</returns>
    ValueTask<GuardrailResult> EvaluateAsync(
        GuardrailContext context,
        CancellationToken cancellationToken = default);
}
