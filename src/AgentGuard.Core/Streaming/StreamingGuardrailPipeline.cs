using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Text;
using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Guardrails;
using AgentGuard.Core.Rules.LLM;
using AgentGuard.Core.Telemetry;
using Microsoft.Extensions.Logging;

namespace AgentGuard.Core.Streaming;

/// <summary>
/// A streaming guardrail pipeline that evaluates text chunks progressively as they arrive.
/// Yields chunks immediately to the consumer while periodically running output guardrails
/// on the accumulated text. If a violation is detected mid-stream, emits retraction and
/// replacement events so the UI can hide/replace content already shown.
/// </summary>
/// <remarks>
/// This follows the pattern used by Azure OpenAI content filters: tokens stream through
/// to the user, and if a violation is detected mid-stream, a retraction/replacement event
/// signals the UI to remove partial output.
/// </remarks>
public sealed partial class StreamingGuardrailPipeline
{
    private readonly IGuardrailPolicy _policy;
    private readonly ProgressiveStreamingOptions _options;
    private readonly ILogger _logger;

    /// <summary>
    /// Creates a new streaming guardrail pipeline.
    /// </summary>
    /// <param name="policy">The guardrail policy containing output rules to evaluate.</param>
    /// <param name="options">Configuration for progressive evaluation intervals.</param>
    /// <param name="logger">Logger instance.</param>
    public StreamingGuardrailPipeline(
        IGuardrailPolicy policy,
        ProgressiveStreamingOptions? options = null,
        ILogger<StreamingGuardrailPipeline>? logger = null)
    {
        _policy = policy ?? throw new ArgumentNullException(nameof(policy));
        _options = options ?? new ProgressiveStreamingOptions();
        _logger = logger ?? Microsoft.Extensions.Logging.Abstractions.NullLogger<StreamingGuardrailPipeline>.Instance;
    }

    /// <summary>
    /// Processes a stream of text chunks, yielding them immediately while running progressive
    /// guardrail evaluations. Emits guardrail events on violations.
    /// </summary>
    /// <param name="textChunks">The incoming stream of text chunks from the LLM.</param>
    /// <param name="baseContext">Base context for guardrail evaluation (phase should be Output).</param>
    /// <param name="violationHandler">Handler to produce replacement text on violations.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A stream of outputs: text chunks, guardrail events, and a completion signal.</returns>
    public async IAsyncEnumerable<StreamingPipelineOutput> ProcessStreamAsync(
        IAsyncEnumerable<string> textChunks,
        GuardrailContext baseContext,
        IViolationHandler? violationHandler = null,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        using var streamingActivity = AgentGuardTelemetry.ActivitySource.StartActivity(
            AgentGuardTelemetry.Spans.StreamingPipeline);

        streamingActivity?.SetTag(AgentGuardTelemetry.Tags.PolicyName, _policy.Name);

        var handler = violationHandler ?? _policy.ViolationHandler;
        var accumulatedText = new StringBuilder();
        var charsSinceLastCheck = 0;
        var lastCheckTime = DateTime.UtcNow;
        var adaptiveRuleLastCheckChars = new Dictionary<string, int>();
        var firstCheckDone = false;
        var totalYieldedChars = 0;

        // classify rules into progressive and final-only
        var (progressiveRules, finalOnlyRules, adaptiveRules) = ClassifyOutputRules();

        LogProgressiveStart(_logger, progressiveRules.Count, finalOnlyRules.Count, adaptiveRules.Count);
        streamingActivity?.SetTag("agentguard.streaming.progressive_rules", progressiveRules.Count);
        streamingActivity?.SetTag("agentguard.streaming.final_only_rules", finalOnlyRules.Count);
        streamingActivity?.SetTag("agentguard.streaming.adaptive_rules", adaptiveRules.Count);

        await foreach (var chunk in textChunks.WithCancellation(cancellationToken))
        {
            if (string.IsNullOrEmpty(chunk))
                continue;

            accumulatedText.Append(chunk);
            charsSinceLastCheck += chunk.Length;
            totalYieldedChars += chunk.Length;

            // yield the chunk immediately
            yield return StreamingPipelineOutput.Chunk(chunk);

            // check if progressive evaluation is due
            if (ShouldEvaluate(accumulatedText.Length, charsSinceLastCheck, lastCheckTime, firstCheckDone))
            {
                var currentText = accumulatedText.ToString();

                // build the set of rules to evaluate this cycle
                var rulesToRun = GetRulesForThisCycle(
                    progressiveRules, adaptiveRules, adaptiveRuleLastCheckChars, accumulatedText.Length);

                if (rulesToRun.Count > 0)
                {
                    var result = await EvaluateRules(rulesToRun, currentText, baseContext, cancellationToken);

                    if (result.IsBlocked)
                    {
                        LogProgressiveViolation(_logger, result.BlockingResult!.RuleName, totalYieldedChars);

                        AgentGuardTelemetry.StreamingRetractions.Add(1,
                            new KeyValuePair<string, object?>(AgentGuardTelemetry.Tags.PolicyName, _policy.Name));

                        var replacementText = await handler.HandleViolationAsync(
                            result.BlockingResult!, baseContext, cancellationToken);

                        streamingActivity?.SetTag(AgentGuardTelemetry.Tags.Outcome, AgentGuardTelemetry.Outcomes.Blocked);
                        streamingActivity?.SetStatus(ActivityStatusCode.Error, result.BlockingResult!.Reason);

                        yield return StreamingPipelineOutput.Event(
                            StreamingGuardrailEvent.Retract(result.BlockingResult!, totalYieldedChars));
                        yield return StreamingPipelineOutput.Event(
                            StreamingGuardrailEvent.Replace(replacementText, result.BlockingResult!, totalYieldedChars));
                        yield return StreamingPipelineOutput.Complete(
                            StreamingFinalResult.Blocked(replacementText, result.BlockingResult!));
                        yield break;
                    }

                    // handle modifications mid-stream (retract and replace with modified text)
                    if (result.WasModified)
                    {
                        var modifyingResult = result.AllResults.FirstOrDefault(r => r.IsModified)
                            ?? GuardrailResult.Passed();

                        LogProgressiveModification(_logger, totalYieldedChars);

                        AgentGuardTelemetry.StreamingRetractions.Add(1,
                            new KeyValuePair<string, object?>(AgentGuardTelemetry.Tags.PolicyName, _policy.Name));
                        AgentGuardTelemetry.Modifications.Add(1,
                            new KeyValuePair<string, object?>(AgentGuardTelemetry.Tags.PolicyName, _policy.Name));

                        streamingActivity?.SetTag(AgentGuardTelemetry.Tags.Outcome, AgentGuardTelemetry.Outcomes.Modified);

                        yield return StreamingPipelineOutput.Event(
                            StreamingGuardrailEvent.Retract(modifyingResult, totalYieldedChars));
                        yield return StreamingPipelineOutput.Event(
                            StreamingGuardrailEvent.Replace(result.FinalText, modifyingResult, totalYieldedChars));
                        yield return StreamingPipelineOutput.Complete(
                            StreamingFinalResult.Modified(result.FinalText));
                        yield break;
                    }
                }

                charsSinceLastCheck = 0;
                lastCheckTime = DateTime.UtcNow;
                firstCheckDone = true;
            }
        }

        // final check: run ALL output rules (including FinalOnly) on the complete text
        if (_options.RunFinalCheck && accumulatedText.Length > 0)
        {
            var fullText = accumulatedText.ToString();
            var allOutputRules = _policy.Rules
                .Where(r => r.Phase.HasFlag(GuardrailPhase.Output))
                .OrderBy(r => r.Order)
                .ToList();

            var finalResult = await EvaluateRules(allOutputRules, fullText, baseContext, cancellationToken);

            if (finalResult.IsBlocked)
            {
                LogFinalViolation(_logger, finalResult.BlockingResult!.RuleName);

                AgentGuardTelemetry.StreamingRetractions.Add(1,
                    new KeyValuePair<string, object?>(AgentGuardTelemetry.Tags.PolicyName, _policy.Name));

                var replacementText = await handler.HandleViolationAsync(
                    finalResult.BlockingResult!, baseContext, cancellationToken);

                streamingActivity?.SetTag(AgentGuardTelemetry.Tags.Outcome, AgentGuardTelemetry.Outcomes.Blocked);
                streamingActivity?.SetStatus(ActivityStatusCode.Error, finalResult.BlockingResult!.Reason);

                yield return StreamingPipelineOutput.Event(
                    StreamingGuardrailEvent.Retract(finalResult.BlockingResult!, totalYieldedChars));
                yield return StreamingPipelineOutput.Event(
                    StreamingGuardrailEvent.Replace(replacementText, finalResult.BlockingResult!, totalYieldedChars));
                yield return StreamingPipelineOutput.Complete(
                    StreamingFinalResult.Blocked(replacementText, finalResult.BlockingResult!));
                yield break;
            }

            if (finalResult.WasModified)
            {
                LogFinalModification(_logger);

                AgentGuardTelemetry.StreamingRetractions.Add(1,
                    new KeyValuePair<string, object?>(AgentGuardTelemetry.Tags.PolicyName, _policy.Name));
                AgentGuardTelemetry.Modifications.Add(1,
                    new KeyValuePair<string, object?>(AgentGuardTelemetry.Tags.PolicyName, _policy.Name));

                streamingActivity?.SetTag(AgentGuardTelemetry.Tags.Outcome, AgentGuardTelemetry.Outcomes.Modified);

                yield return StreamingPipelineOutput.Event(
                    StreamingGuardrailEvent.Retract(
                        finalResult.AllResults.FirstOrDefault(r => r.IsModified) ?? GuardrailResult.Passed(),
                        totalYieldedChars));
                yield return StreamingPipelineOutput.Event(
                    StreamingGuardrailEvent.Replace(
                        finalResult.FinalText,
                        finalResult.AllResults.FirstOrDefault(r => r.IsModified) ?? GuardrailResult.Passed(),
                        totalYieldedChars));
                yield return StreamingPipelineOutput.Complete(
                    StreamingFinalResult.Modified(finalResult.FinalText));
                yield break;
            }
        }

        streamingActivity?.SetTag(AgentGuardTelemetry.Tags.Outcome, AgentGuardTelemetry.Outcomes.Passed);
        yield return StreamingPipelineOutput.Complete(StreamingFinalResult.Pass());
    }

    private bool ShouldEvaluate(int totalChars, int charsSinceLastCheck, DateTime lastCheckTime, bool firstCheckDone)
    {
        // haven't accumulated enough for the first check
        if (!firstCheckDone && totalChars < _options.MinCharsBeforeFirstCheck)
            return false;

        // character interval
        if (charsSinceLastCheck >= _options.EvaluationIntervalChars)
            return true;

        // time interval
        if (_options.EvaluationIntervalTime.HasValue &&
            DateTime.UtcNow - lastCheckTime >= _options.EvaluationIntervalTime.Value)
            return true;

        return false;
    }

    private (List<IGuardrailRule> progressive, List<IGuardrailRule> finalOnly, List<IGuardrailRule> adaptive) ClassifyOutputRules()
    {
        var progressive = new List<IGuardrailRule>();
        var finalOnly = new List<IGuardrailRule>();
        var adaptive = new List<IGuardrailRule>();

        foreach (var rule in _policy.Rules.Where(r => r.Phase.HasFlag(GuardrailPhase.Output)).OrderBy(r => r.Order))
        {
            var mode = GetStreamingMode(rule);
            switch (mode)
            {
                case StreamingEvaluationMode.EveryCheck:
                    progressive.Add(rule);
                    break;
                case StreamingEvaluationMode.FinalOnly:
                    finalOnly.Add(rule);
                    break;
                case StreamingEvaluationMode.Adaptive:
                    adaptive.Add(rule);
                    break;
            }
        }

        return (progressive, finalOnly, adaptive);
    }

    private static StreamingEvaluationMode GetStreamingMode(IGuardrailRule rule)
    {
        // if the rule explicitly declares its streaming mode, use it
        if (rule is IStreamingGuardrailRule streamingRule)
            return streamingRule.StreamingMode;

        // default heuristic: LLM rules are FinalOnly, all others are EveryCheck
        if (rule is LlmGuardrailRule)
            return StreamingEvaluationMode.FinalOnly;

        return StreamingEvaluationMode.EveryCheck;
    }

    private List<IGuardrailRule> GetRulesForThisCycle(
        List<IGuardrailRule> progressiveRules,
        List<IGuardrailRule> adaptiveRules,
        Dictionary<string, int> adaptiveLastCheck,
        int currentTotalChars)
    {
        var rules = new List<IGuardrailRule>(progressiveRules);

        foreach (var rule in adaptiveRules)
        {
            if (!adaptiveLastCheck.TryGetValue(rule.Name, out var lastCheck))
                lastCheck = 0;

            // check MinTokensBeforeFirstCheck
            if (rule is IStreamingGuardrailRule streamingRule &&
                currentTotalChars < streamingRule.MinTokensBeforeFirstCheck * 4) // rough char-to-token heuristic
                continue;

            if (currentTotalChars - lastCheck >= _options.AdaptiveRuleMinCharInterval)
            {
                rules.Add(rule);
                adaptiveLastCheck[rule.Name] = currentTotalChars;
            }
        }

        return rules.OrderBy(r => r.Order).ToList();
    }

    private async ValueTask<GuardrailPipelineResult> EvaluateRules(
        List<IGuardrailRule> rules,
        string text,
        GuardrailContext baseContext,
        CancellationToken cancellationToken)
    {
        var results = new List<GuardrailResult>();
        var currentText = text;

        foreach (var rule in rules)
        {
            cancellationToken.ThrowIfCancellationRequested();

            LogRunningRule(_logger, rule.Name, "progressive");

            var context = baseContext with { Text = currentText };

            using var ruleActivity = AgentGuardTelemetry.ActivitySource.StartActivity(
                $"{AgentGuardTelemetry.Spans.RuleEvaluate} {rule.Name}");

            ruleActivity?.SetTag(AgentGuardTelemetry.Tags.RuleName, rule.Name);
            ruleActivity?.SetTag(AgentGuardTelemetry.Tags.Phase, "output");
            ruleActivity?.SetTag(AgentGuardTelemetry.Tags.RuleOrder, rule.Order);
            ruleActivity?.SetTag(AgentGuardTelemetry.Tags.StreamingStrategy, "progressive");

            var stopwatch = ValueStopwatch.StartNew();
            var result = await rule.EvaluateAsync(context, cancellationToken);
            var elapsed = stopwatch.GetElapsedMilliseconds();

            var outcome = result.IsBlocked ? AgentGuardTelemetry.Outcomes.Blocked
                : result.IsModified ? AgentGuardTelemetry.Outcomes.Modified
                : result.IsError ? AgentGuardTelemetry.Outcomes.Error
                : AgentGuardTelemetry.Outcomes.Passed;

            ruleActivity?.SetTag(AgentGuardTelemetry.Tags.Outcome, outcome);

            AgentGuardTelemetry.RuleEvaluations.Add(1,
                new KeyValuePair<string, object?>(AgentGuardTelemetry.Tags.RuleName, rule.Name),
                new KeyValuePair<string, object?>(AgentGuardTelemetry.Tags.Phase, "output"),
                new KeyValuePair<string, object?>(AgentGuardTelemetry.Tags.Outcome, outcome));

            AgentGuardTelemetry.RuleDuration.Record(elapsed,
                new KeyValuePair<string, object?>(AgentGuardTelemetry.Tags.RuleName, rule.Name),
                new KeyValuePair<string, object?>(AgentGuardTelemetry.Tags.Phase, "output"));

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
                ruleActivity?.SetStatus(ActivityStatusCode.Error, result.Reason);

                AgentGuardTelemetry.RuleBlocks.Add(1,
                    new KeyValuePair<string, object?>(AgentGuardTelemetry.Tags.RuleName, rule.Name),
                    new KeyValuePair<string, object?>(AgentGuardTelemetry.Tags.Severity, result.Severity.ToString().ToLowerInvariant()));

                return new GuardrailPipelineResult
                {
                    IsBlocked = true,
                    BlockingResult = taggedResult,
                    AllResults = results,
                    FinalText = currentText
                };
            }

            if (result.IsModified && result.ModifiedText is not null)
            {
                currentText = result.ModifiedText;
            }

            if (!result.IsBlocked && !result.IsModified && !result.IsError)
            {
                LogRulePassed(_logger, rule.Name);
            }
        }

        return new GuardrailPipelineResult
        {
            IsBlocked = false,
            AllResults = results,
            FinalText = currentText,
            WasModified = currentText != text
        };
    }

    [LoggerMessage(Level = LogLevel.Debug, Message = "Progressive streaming started: {ProgressiveCount} progressive rules, {FinalOnlyCount} final-only rules, {AdaptiveCount} adaptive rules")]
    private static partial void LogProgressiveStart(ILogger logger, int progressiveCount, int finalOnlyCount, int adaptiveCount);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Progressive guardrail violation by '{RuleName}' after {YieldedChars} chars yielded - retracting")]
    private static partial void LogProgressiveViolation(ILogger logger, string ruleName, int yieldedChars);

    [LoggerMessage(Level = LogLevel.Information, Message = "Progressive guardrail modification after {YieldedChars} chars yielded - retracting and replacing")]
    private static partial void LogProgressiveModification(ILogger logger, int yieldedChars);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Final guardrail check violation by '{RuleName}' - retracting all yielded content")]
    private static partial void LogFinalViolation(ILogger logger, string ruleName);

    [LoggerMessage(Level = LogLevel.Information, Message = "Final guardrail check modified content - retracting and replacing")]
    private static partial void LogFinalModification(ILogger logger);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Running streaming guardrail rule '{RuleName}' ({Mode})")]
    private static partial void LogRunningRule(ILogger logger, string ruleName, string mode);

    [LoggerMessage(Level = LogLevel.Trace, Message = "Streaming guardrail rule '{RuleName}' PASSED")]
    private static partial void LogRulePassed(ILogger logger, string ruleName);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Streaming guardrail rule '{RuleName}' encountered an error: {ErrorDetail} (blocked={IsBlocked})")]
    private static partial void LogRuleError(ILogger logger, string ruleName, string? errorDetail, bool isBlocked);
}
