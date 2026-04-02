using System.Diagnostics;
using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Telemetry;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.Logging;

namespace AgentGuard.Core.Guardrails;

public sealed partial class GuardrailPipeline
{
    private readonly IGuardrailPolicy _policy;
    private readonly ILogger<GuardrailPipeline> _logger;

    public GuardrailPipeline(IGuardrailPolicy policy, ILogger<GuardrailPipeline> logger)
    {
        _policy = policy;
        _logger = logger;
    }

    public async ValueTask<GuardrailPipelineResult> RunAsync(
        GuardrailContext context, CancellationToken cancellationToken = default)
    {
        var coreResult = await RunCoreAsync(context, cancellationToken);

        if (coreResult.IsBlocked
            && context.Phase == GuardrailPhase.Output
            && _policy.ReaskOptions is { } reaskOptions
            && _policy.ReaskChatClient is { } chatClient)
        {
            return await RunReaskLoopAsync(context, coreResult, reaskOptions, chatClient, cancellationToken);
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

        foreach (var rule in phaseRules)
        {
            cancellationToken.ThrowIfCancellationRequested();

            LogRunningRule(_logger, rule.Name, context.Phase);

            var ruleContext = context with { Text = currentText };
            var result = await EvaluateRuleWithTelemetry(rule, ruleContext, cancellationToken);
            var taggedResult = result with { RuleName = rule.Name };
            results.Add(taggedResult);

            if (result.IsError)
            {
                var errorDetail = result.Metadata?.TryGetValue("errorDetail", out var detail) == true
                    ? detail?.ToString() : null;
                LogRuleError(_logger, rule.Name, errorDetail, result.IsBlocked);
            }

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
                pipelineActivity?.SetStatus(ActivityStatusCode.Error, result.Reason);
                return pipelineResult;
            }

            if (result.IsModified && result.ModifiedText is not null)
            {
                LogRuleModified(_logger, rule.Name, result.Reason);
                currentText = result.ModifiedText;
            }

            if (!result.IsBlocked && !result.IsModified && !result.IsError)
            {
                LogRulePassed(_logger, rule.Name);
            }
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

        return new GuardrailPipelineResult
        {
            IsBlocked = false,
            AllResults = results,
            FinalText = currentText,
            WasModified = wasModified
        };
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
        var result = await rule.EvaluateAsync(context, cancellationToken);
        var elapsed = stopwatch.GetElapsedMilliseconds();

        var outcome = result.IsBlocked ? AgentGuardTelemetry.Outcomes.Blocked
            : result.IsModified ? AgentGuardTelemetry.Outcomes.Modified
            : result.IsError ? AgentGuardTelemetry.Outcomes.Error
            : AgentGuardTelemetry.Outcomes.Passed;

        ruleActivity?.SetTag(AgentGuardTelemetry.Tags.Outcome, outcome);

        if (result.IsBlocked)
        {
            ruleActivity?.SetStatus(ActivityStatusCode.Error, result.Reason);
            ruleActivity?.SetTag(AgentGuardTelemetry.Tags.BlockedReason, result.Reason);
            ruleActivity?.SetTag(AgentGuardTelemetry.Tags.Severity, result.Severity.ToString().ToLowerInvariant());
            ruleActivity?.AddEvent(new ActivityEvent("agentguard.rule.blocked", tags: new ActivityTagsCollection
            {
                ["reason"] = result.Reason ?? "",
                ["severity"] = result.Severity.ToString().ToLowerInvariant()
            }));

            AgentGuardTelemetry.RuleBlocks.Add(1,
                new KeyValuePair<string, object?>(AgentGuardTelemetry.Tags.RuleName, rule.Name),
                new KeyValuePair<string, object?>(AgentGuardTelemetry.Tags.Severity, result.Severity.ToString().ToLowerInvariant()));
        }

        if (result.IsError)
        {
            var errorDetail = result.Metadata?.TryGetValue("errorDetail", out var detail) == true
                ? detail?.ToString() : null;
            ruleActivity?.SetTag(AgentGuardTelemetry.Tags.ErrorType, errorDetail ?? "unknown");
        }

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
        IChatClient chatClient,
        CancellationToken cancellationToken)
    {
        using var reaskActivity = AgentGuardTelemetry.ActivitySource.StartActivity(
            AgentGuardTelemetry.Spans.PipelineReask);

        reaskActivity?.SetTag(AgentGuardTelemetry.Tags.ReaskMaxAttempts, options.MaxAttempts);
        reaskActivity?.SetTag(AgentGuardTelemetry.Tags.PolicyName, _policy.Name);

        var currentBlockedResult = blockedResult;

        for (var attempt = 0; attempt < options.MaxAttempts; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var violationReason = currentBlockedResult.BlockingResult?.Reason ?? "Output was blocked by a guardrail.";
            LogReaskAttempt(_logger, attempt + 1, options.MaxAttempts, violationReason);

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
                return reaskResult with
                {
                    WasReasked = true,
                    ReaskAttemptsUsed = attempt + 1
                };
            }

            currentBlockedResult = reaskResult;
        }

        LogReaskExhausted(_logger, options.MaxAttempts);
        reaskActivity?.SetTag(AgentGuardTelemetry.Tags.ReaskAttemptsUsed, options.MaxAttempts);
        reaskActivity?.SetTag(AgentGuardTelemetry.Tags.Outcome, AgentGuardTelemetry.Outcomes.Blocked);
        reaskActivity?.SetStatus(ActivityStatusCode.Error, "Re-ask exhausted all attempts");
        return currentBlockedResult with
        {
            WasReasked = true,
            ReaskAttemptsUsed = options.MaxAttempts
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

    [LoggerMessage(Level = LogLevel.Information, Message = "Re-ask attempt {Attempt}/{MaxAttempts} - violation: {Reason}")]
    private static partial void LogReaskAttempt(ILogger logger, int attempt, int maxAttempts, string reason);

    [LoggerMessage(Level = LogLevel.Information, Message = "Re-ask succeeded on attempt {Attempt}")]
    private static partial void LogReaskSuccess(ILogger logger, int attempt);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Re-ask exhausted all {MaxAttempts} attempts, returning blocked result")]
    private static partial void LogReaskExhausted(ILogger logger, int maxAttempts);
}

public sealed record GuardrailPipelineResult
{
    public required bool IsBlocked { get; init; }
    public bool WasModified { get; init; }
    public GuardrailResult? BlockingResult { get; init; }
    public required IReadOnlyList<GuardrailResult> AllResults { get; init; }
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
