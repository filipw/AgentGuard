using System.Diagnostics;
using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Ledger;
using AgentGuard.Core.Telemetry;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.Logging;

namespace AgentGuard.Core.Guardrails;

/// <summary>
/// Runs a policy's rules in order against one piece of text. Rules see the text as rewritten by
/// whichever rules ran before them, a block short-circuits the rest, and each decision is optionally
/// recorded to a <see cref="IGuardrailLedger"/>.
/// </summary>
public sealed partial class GuardrailPipeline
{
    private readonly IGuardrailPolicy _policy;
    private readonly ILogger<GuardrailPipeline> _logger;
    private readonly IGuardrailLedger? _ledger;

    /// <summary>Initializes a new instance of the <see cref="GuardrailPipeline"/> class.</summary>
    /// <param name="policy">The policy to run.</param>
    /// <param name="logger">Logger for rule outcomes.</param>
    /// <param name="ledger">Optional tamper-evident decision ledger.</param>
    public GuardrailPipeline(IGuardrailPolicy policy, ILogger<GuardrailPipeline> logger, IGuardrailLedger? ledger = null)
    {
        _policy = policy;
        _logger = logger;
        _ledger = ledger;
    }

    /// <summary>
    /// The decision ledger this pipeline records to, or <c>null</c> when no ledger is configured.
    /// </summary>
    public IGuardrailLedger? Ledger => _ledger;

    /// <summary>Evaluates <paramref name="context"/> against every rule for its phase.</summary>
    /// <param name="context">The text and its surrounding state.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The combined outcome, including each rule's individual result.</returns>
    public async ValueTask<GuardrailPipelineResult> RunAsync(
        GuardrailContext context, CancellationToken cancellationToken = default)
    {
        var coreResult = await RunCoreAsync(context, cancellationToken);

        if (coreResult.IsBlocked
            && context.Phase == GuardrailPhase.Output
            && _policy.ReaskOptions is { } reaskOptions
            && _policy.ReaskChatClient is { } chatClient)
        {
            // the options object is mutable and shared by concurrent runs, so the limit is read once.
            // Zero turns re-asking off: the block comes back exactly as the rules produced it.
            var maxAttempts = reaskOptions.MaxAttempts;
            if (maxAttempts > 0)
                return await RunReaskLoopAsync(context, coreResult, reaskOptions, maxAttempts, chatClient, cancellationToken);
        }

        return coreResult;
    }

    private async ValueTask<GuardrailPipelineResult> RunCoreAsync(
        GuardrailContext context, CancellationToken cancellationToken)
    {
        using var pipelineActivity = AgentGuardTelemetry.ActivitySource.StartActivity(
            AgentGuardTelemetry.Spans.PipelineRun);

        pipelineActivity?.SetTag(AgentGuardTelemetry.Tags.PolicyName, _policy.Name);
        pipelineActivity?.SetTag(AgentGuardTelemetry.Tags.Phase, context.Phase.ToString().ToLowerInvariant());
        if (context.AgentName is not null)
            pipelineActivity?.SetTag(AgentGuardTelemetry.Tags.AgentName, context.AgentName);

        if (AgentGuardTelemetry.EnableSensitiveData)
            pipelineActivity?.AddEvent(new ActivityEvent("agentguard.input", tags: new ActivityTagsCollection
            {
                ["text"] = context.Text
            }));

        var stopwatch = ValueStopwatch.StartNew();

        var results = new List<GuardrailResult>();
        var currentText = context.Text;

        var phaseRules = _policy.Rules
            .Where(r => r.Phase.HasFlag(context.Phase))
            .OrderBy(r => r.Order);

        try
        {
            foreach (var rule in phaseRules)
            {
                cancellationToken.ThrowIfCancellationRequested();

                LogRunningRule(_logger, rule.Name, context.Phase);

                var ruleContext = context with { Text = currentText };
                var result = await EvaluateRuleWithTelemetry(rule, ruleContext, cancellationToken);
                var taggedResult = result with { RuleName = rule.Name };
                results.Add(taggedResult);

                LogErrorOrWarning(rule.Name, result);

                if (result.IsBlocked)
                {
                    LogRuleBlocked(_logger, rule.Name, result.Reason);

                    var pipelineResult = new GuardrailPipelineResult
                    {
                        IsBlocked = true,
                        BlockingResult = taggedResult,
                        AllResults = results,
                        FinalText = currentText
                    };

                    RecordPipelineCompletion(pipelineActivity, stopwatch, context.Phase, AgentGuardTelemetry.Outcomes.Blocked);
                    AgentGuardTelemetry.RecordBlock(pipelineActivity, taggedResult);
                    EmitDecision(context, currentText, results, AgentGuardTelemetry.Outcomes.Blocked, taggedResult, wasModified: false);
                    return pipelineResult;
                }

                if (result.IsModified && result.ModifiedText is not null)
                {
                    LogRuleModified(_logger, rule.Name, result.Reason);
                    currentText = result.ModifiedText;
                }

                if (!result.IsBlocked && !result.IsModified && !result.IsError && !result.IsWarning)
                {
                    LogRulePassed(_logger, rule.Name);
                }
            }
        }
        catch (Exception ex)
        {
            AgentGuardTelemetry.RecordException(pipelineActivity, ex, cancellationToken);
            throw;
        }

        var wasModified = currentText != context.Text;
        var outcome = wasModified ? AgentGuardTelemetry.Outcomes.Modified : AgentGuardTelemetry.Outcomes.Passed;
        RecordPipelineCompletion(pipelineActivity, stopwatch, context.Phase, outcome);

        if (wasModified)
        {
            AgentGuardTelemetry.Modifications.Add(1,
                new KeyValuePair<string, object?>(AgentGuardTelemetry.Tags.PolicyName, _policy.Name),
                new KeyValuePair<string, object?>(AgentGuardTelemetry.Tags.Phase, context.Phase.ToString().ToLowerInvariant()));
        }

        if (AgentGuardTelemetry.EnableSensitiveData)
            pipelineActivity?.AddEvent(new ActivityEvent("agentguard.output", tags: new ActivityTagsCollection
            {
                ["text"] = currentText
            }));

        EmitDecision(context, currentText, results, outcome, blockingResult: null, wasModified);

        return new GuardrailPipelineResult
        {
            IsBlocked = false,
            AllResults = results,
            FinalText = currentText,
            WasModified = wasModified
        };
    }

    // an error under FailOpen is logged at Debug; one that blocks (FailClosed) or asked to be surfaced
    // (Warn) is logged at Warning, as is any other result that passed with a warning
    private void LogErrorOrWarning(string ruleName, GuardrailResult result)
    {
        if (result.IsError)
        {
            var errorDetail = AgentGuardTelemetry.ErrorDetail(result);
            if (result.IsBlocked || result.IsWarning)
                LogRuleError(_logger, ruleName, errorDetail, result.IsBlocked);
            else
                LogRuleErrorFailedOpen(_logger, ruleName, errorDetail);
        }
        else if (result.IsWarning && !result.IsBlocked)
        {
            LogRuleWarning(_logger, ruleName, result.Reason);
        }
    }

    private void EmitDecision(
        GuardrailContext context,
        string finalText,
        List<GuardrailResult> results,
        string outcome,
        GuardrailResult? blockingResult,
        bool wasModified)
    {
        if (_ledger is null)
            return;

        // the ledger is an audit side-channel: a failure to record (e.g. a JSONL write
        // error) must never break guardrail evaluation, so emission is fail-open.
        try
        {
            var decision = GuardrailDecisionFactory.Create(
                _policy.Name, context, finalText, results, outcome, blockingResult, wasModified);
            _ledger.Append(decision);
        }
        catch (Exception ex)
        {
            LogLedgerError(_logger, ex);
        }
    }

    private static async ValueTask<GuardrailResult> EvaluateRuleWithTelemetry(
        IGuardrailRule rule, GuardrailContext context, CancellationToken cancellationToken)
    {
        using var ruleActivity = AgentGuardTelemetry.ActivitySource.StartActivity(
            $"{AgentGuardTelemetry.Spans.RuleEvaluate} {rule.Name}");

        ruleActivity?.SetTag(AgentGuardTelemetry.Tags.RuleName, rule.Name);
        ruleActivity?.SetTag(AgentGuardTelemetry.Tags.Phase, context.Phase.ToString().ToLowerInvariant());
        ruleActivity?.SetTag(AgentGuardTelemetry.Tags.RuleOrder, rule.Order);

        var stopwatch = ValueStopwatch.StartNew();
        GuardrailResult result;
        try
        {
            result = await rule.EvaluateAsync(context, cancellationToken);
        }
        catch (Exception ex)
        {
            AgentGuardTelemetry.RecordException(ruleActivity, ex, cancellationToken);
            throw;
        }

        var elapsed = stopwatch.GetElapsedMilliseconds();

        var outcome = AgentGuardTelemetry.OutcomeOf(result);
        ruleActivity?.SetTag(AgentGuardTelemetry.Tags.Outcome, outcome);

        if (result.IsBlocked)
        {
            var severity = AgentGuardTelemetry.SeverityTag(result.Severity);
            AgentGuardTelemetry.RecordBlock(ruleActivity, result);
            ruleActivity?.AddEvent(new ActivityEvent("agentguard.rule.blocked", tags: new ActivityTagsCollection
            {
                ["reason"] = result.Reason ?? "",
                ["severity"] = severity
            }));

            AgentGuardTelemetry.RuleBlocks.Add(1,
                new KeyValuePair<string, object?>(AgentGuardTelemetry.Tags.RuleName, rule.Name),
                new KeyValuePair<string, object?>(AgentGuardTelemetry.Tags.Severity, severity));
        }

        // a rule that could not reach a verdict is a failure, whatever its ErrorBehavior let the text do
        if (result.IsError)
            AgentGuardTelemetry.RecordRuleError(ruleActivity, result);

        AgentGuardTelemetry.RuleEvaluations.Add(1,
            new KeyValuePair<string, object?>(AgentGuardTelemetry.Tags.RuleName, rule.Name),
            new KeyValuePair<string, object?>(AgentGuardTelemetry.Tags.Phase, context.Phase.ToString().ToLowerInvariant()),
            new KeyValuePair<string, object?>(AgentGuardTelemetry.Tags.Outcome, outcome));

        AgentGuardTelemetry.RuleDuration.Record(elapsed,
            new KeyValuePair<string, object?>(AgentGuardTelemetry.Tags.RuleName, rule.Name),
            new KeyValuePair<string, object?>(AgentGuardTelemetry.Tags.Phase, context.Phase.ToString().ToLowerInvariant()));

        return result;
    }

    private void RecordPipelineCompletion(Activity? activity, ValueStopwatch stopwatch, GuardrailPhase phase, string outcome)
    {
        var elapsed = stopwatch.GetElapsedMilliseconds();

        activity?.SetTag(AgentGuardTelemetry.Tags.Outcome, outcome);

        AgentGuardTelemetry.PipelineEvaluations.Add(1,
            new KeyValuePair<string, object?>(AgentGuardTelemetry.Tags.PolicyName, _policy.Name),
            new KeyValuePair<string, object?>(AgentGuardTelemetry.Tags.Phase, phase.ToString().ToLowerInvariant()),
            new KeyValuePair<string, object?>(AgentGuardTelemetry.Tags.Outcome, outcome));

        AgentGuardTelemetry.PipelineDuration.Record(elapsed,
            new KeyValuePair<string, object?>(AgentGuardTelemetry.Tags.PolicyName, _policy.Name),
            new KeyValuePair<string, object?>(AgentGuardTelemetry.Tags.Phase, phase.ToString().ToLowerInvariant()),
            new KeyValuePair<string, object?>(AgentGuardTelemetry.Tags.Outcome, outcome));
    }

    private async ValueTask<GuardrailPipelineResult> RunReaskLoopAsync(
        GuardrailContext originalContext,
        GuardrailPipelineResult blockedResult,
        ReaskOptions options,
        int maxAttempts,
        IChatClient chatClient,
        CancellationToken cancellationToken)
    {
        using var reaskActivity = AgentGuardTelemetry.ActivitySource.StartActivity(
            AgentGuardTelemetry.Spans.PipelineReask);

        reaskActivity?.SetTag(AgentGuardTelemetry.Tags.ReaskMaxAttempts, maxAttempts);
        reaskActivity?.SetTag(AgentGuardTelemetry.Tags.PolicyName, _policy.Name);

        var currentBlockedResult = blockedResult;

        try
        {
            for (var attempt = 0; attempt < maxAttempts; attempt++)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var violationReason = currentBlockedResult.BlockingResult?.Reason ?? "Output was blocked by a guardrail.";
                LogReaskAttempt(_logger, attempt + 1, maxAttempts, violationReason);

                AgentGuardTelemetry.ReaskAttempts.Add(1,
                    new KeyValuePair<string, object?>(AgentGuardTelemetry.Tags.PolicyName, _policy.Name));

                var reaskMessages = BuildReaskMessages(originalContext, currentBlockedResult, options);
                var response = await chatClient.GetResponseAsync(reaskMessages, options.ChatOptions, cancellationToken);
                var newText = response.Text ?? "";

                var reaskContext = originalContext with { Text = newText };
                var reaskResult = await RunCoreAsync(reaskContext, cancellationToken);

                if (!reaskResult.IsBlocked)
                {
                    LogReaskSuccess(_logger, attempt + 1);
                    reaskActivity?.SetTag(AgentGuardTelemetry.Tags.ReaskAttemptsUsed, attempt + 1);
                    reaskActivity?.SetTag(AgentGuardTelemetry.Tags.Outcome, AgentGuardTelemetry.Outcomes.Passed);

                    // the core run compared the re-asked text with itself; against the caller's text the answer
                    // changed, and the adapters apply FinalText when WasModified is set
                    return reaskResult with
                    {
                        WasModified = !string.Equals(reaskResult.FinalText, originalContext.Text, StringComparison.Ordinal),
                        WasReasked = true,
                        ReaskAttemptsUsed = attempt + 1
                    };
                }

                currentBlockedResult = reaskResult;
            }
        }
        catch (Exception ex)
        {
            AgentGuardTelemetry.RecordException(reaskActivity, ex, cancellationToken);
            throw;
        }

        // running out of attempts is recorded like any other block: an expected outcome, not a failure
        LogReaskExhausted(_logger, maxAttempts);
        reaskActivity?.SetTag(AgentGuardTelemetry.Tags.ReaskAttemptsUsed, maxAttempts);
        reaskActivity?.SetTag(AgentGuardTelemetry.Tags.Outcome, AgentGuardTelemetry.Outcomes.Blocked);
        if (currentBlockedResult.BlockingResult is { } blockingResult)
            AgentGuardTelemetry.RecordBlock(reaskActivity, blockingResult);

        return currentBlockedResult with
        {
            WasReasked = true,
            ReaskAttemptsUsed = maxAttempts
        };
    }

    private static List<ChatMessage> BuildReaskMessages(
        GuardrailContext originalContext,
        GuardrailPipelineResult blockedResult,
        ReaskOptions options)
    {
        var messages = new List<ChatMessage>();

        var violationReason = blockedResult.BlockingResult?.Reason ?? "Output was blocked by a guardrail.";
        var systemPrompt = options.SystemPromptTemplate
            .Replace("{violation_reason}", violationReason)
            .Replace("{original_response}", blockedResult.FinalText);

        messages.Add(new ChatMessage(ChatRole.System, systemPrompt));

        // include the original conversation context if available
        if (originalContext.Messages is { Count: > 0 } contextMessages)
        {
            messages.AddRange(contextMessages);
        }

        // include the blocked response so the LLM knows what to avoid
        if (options.IncludeBlockedResponse)
        {
            messages.Add(new ChatMessage(ChatRole.Assistant, blockedResult.FinalText));
            messages.Add(new ChatMessage(ChatRole.User,
                $"That response was rejected because: {violationReason}. Please try again."));
        }

        return messages;
    }

    [LoggerMessage(Level = LogLevel.Debug, Message = "Running guardrail rule '{RuleName}' in phase {Phase}")]
    private static partial void LogRunningRule(ILogger logger, string ruleName, GuardrailPhase phase);

    [LoggerMessage(Level = LogLevel.Trace, Message = "Guardrail rule '{RuleName}' PASSED")]
    private static partial void LogRulePassed(ILogger logger, string ruleName);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Guardrail rule '{RuleName}' BLOCKED: {Reason}")]
    private static partial void LogRuleBlocked(ILogger logger, string ruleName, string? reason);

    [LoggerMessage(Level = LogLevel.Information, Message = "Guardrail rule '{RuleName}' modified text: {Reason}")]
    private static partial void LogRuleModified(ILogger logger, string ruleName, string? reason);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Guardrail rule '{RuleName}' encountered an error: {ErrorDetail} (blocked={IsBlocked})")]
    private static partial void LogRuleError(ILogger logger, string ruleName, string? errorDetail, bool isBlocked);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Guardrail rule '{RuleName}' encountered an error and failed open: {ErrorDetail}")]
    private static partial void LogRuleErrorFailedOpen(ILogger logger, string ruleName, string? errorDetail);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Guardrail rule '{RuleName}' passed with a warning: {Reason}")]
    private static partial void LogRuleWarning(ILogger logger, string ruleName, string? reason);

    [LoggerMessage(Level = LogLevel.Information, Message = "Re-ask attempt {Attempt}/{MaxAttempts} - violation: {Reason}")]
    private static partial void LogReaskAttempt(ILogger logger, int attempt, int maxAttempts, string reason);

    [LoggerMessage(Level = LogLevel.Information, Message = "Re-ask succeeded on attempt {Attempt}")]
    private static partial void LogReaskSuccess(ILogger logger, int attempt);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Re-ask exhausted all {MaxAttempts} attempts, returning blocked result")]
    private static partial void LogReaskExhausted(ILogger logger, int maxAttempts);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Failed to record guardrail decision to the ledger; continuing (audit side-channel)")]
    private static partial void LogLedgerError(ILogger logger, Exception exception);
}

/// <summary>The outcome of one pipeline run.</summary>
public sealed record GuardrailPipelineResult
{
    /// <summary>Whether a rule rejected the text.</summary>
    public required bool IsBlocked { get; init; }

    /// <summary>
    /// Whether <see cref="FinalText"/> differs from the text that went in - including when a successful
    /// re-ask replaced it with a new answer.
    /// </summary>
    public bool WasModified { get; init; }

    /// <summary>The rule result that blocked, when <see cref="IsBlocked"/> is true.</summary>
    public GuardrailResult? BlockingResult { get; init; }

    /// <summary>Every rule result produced, in execution order, up to and including any block.</summary>
    public required IReadOnlyList<GuardrailResult> AllResults { get; init; }

    /// <summary>
    /// The results in <see cref="AllResults"/> that let the text through but asked to be surfaced
    /// (<see cref="GuardrailResult.IsWarning"/>), such as a rule that could not reach a verdict under
    /// <see cref="ErrorBehavior.Warn"/>. Empty when there are none. A rule that failed under
    /// <see cref="ErrorBehavior.FailOpen"/> is not listed here; it is in <see cref="AllResults"/> with
    /// <see cref="GuardrailResult.IsError"/> set.
    /// </summary>
    public IReadOnlyList<GuardrailResult> Warnings => AllResults.Where(r => r.IsWarning && !r.IsBlocked).ToArray();

    /// <summary>The text after every modification. On a block, the text as it stood when blocked.</summary>
    public required string FinalText { get; init; }

    /// <summary>
    /// Whether the pipeline performed at least one re-ask attempt.
    /// </summary>
    public bool WasReasked { get; init; }

    /// <summary>
    /// Number of re-ask attempts used. Zero when re-ask is not enabled or the first response passed.
    /// </summary>
    public int ReaskAttemptsUsed { get; init; }
}

/// <summary>
/// Lightweight stopwatch using <see cref="Stopwatch.GetTimestamp"/> to avoid allocations.
/// </summary>
internal readonly struct ValueStopwatch
{
    private readonly long _startTimestamp;

    private ValueStopwatch(long startTimestamp) => _startTimestamp = startTimestamp;

    public static ValueStopwatch StartNew() => new(Stopwatch.GetTimestamp());

    public double GetElapsedMilliseconds() =>
        Stopwatch.GetElapsedTime(_startTimestamp).TotalMilliseconds;
}
