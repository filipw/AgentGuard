using System.Runtime.CompilerServices;
using System.Text;
using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Guardrails;
using AgentGuard.Core.Rules.LLM;
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
        var handler = violationHandler ?? _policy.ViolationHandler;
        var accumulatedText = new StringBuilder();
        var charsSinceLastCheck = 0;
        var lastCheckTime = DateTime.UtcNow;
        var adaptiveRuleLastCheckChars = new Dictionary<string, int>();
        var firstCheckDone = false;
        var totalYieldedChars = 0;

        // Classify rules into progressive and final-only
        var (progressiveRules, finalOnlyRules, adaptiveRules) = ClassifyOutputRules();

        LogProgressiveStart(_logger, progressiveRules.Count, finalOnlyRules.Count, adaptiveRules.Count);

        await foreach (var chunk in textChunks.WithCancellation(cancellationToken))
        {
            if (string.IsNullOrEmpty(chunk))
                continue;

            accumulatedText.Append(chunk);
            charsSinceLastCheck += chunk.Length;
            totalYieldedChars += chunk.Length;

            // Yield the chunk immediately
            yield return StreamingPipelineOutput.Chunk(chunk);

            // Check if progressive evaluation is due
            if (ShouldEvaluate(accumulatedText.Length, charsSinceLastCheck, lastCheckTime, firstCheckDone))
            {
                var currentText = accumulatedText.ToString();

                // Build the set of rules to evaluate this cycle
                var rulesToRun = GetRulesForThisCycle(
                    progressiveRules, adaptiveRules, adaptiveRuleLastCheckChars, accumulatedText.Length);

                if (rulesToRun.Count > 0)
                {
                    var result = await EvaluateRules(rulesToRun, currentText, baseContext, cancellationToken);

                    if (result.IsBlocked)
                    {
                        LogProgressiveViolation(_logger, result.BlockingResult!.RuleName, totalYieldedChars);

                        var replacementText = await handler.HandleViolationAsync(
                            result.BlockingResult!, baseContext, cancellationToken);

                        yield return StreamingPipelineOutput.Event(
                            StreamingGuardrailEvent.Retract(result.BlockingResult!, totalYieldedChars));
                        yield return StreamingPipelineOutput.Event(
                            StreamingGuardrailEvent.Replace(replacementText, result.BlockingResult!, totalYieldedChars));
                        yield return StreamingPipelineOutput.Complete(
                            StreamingFinalResult.Blocked(replacementText, result.BlockingResult!));
                        yield break;
                    }

                    // Handle modifications mid-stream (retract and replace with modified text)
                    if (result.WasModified)
                    {
                        var modifyingResult = result.AllResults.FirstOrDefault(r => r.IsModified)
                            ?? GuardrailResult.Passed();

                        LogProgressiveModification(_logger, totalYieldedChars);

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

        // Final check: run ALL output rules (including FinalOnly) on the complete text
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

                var replacementText = await handler.HandleViolationAsync(
                    finalResult.BlockingResult!, baseContext, cancellationToken);

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

        yield return StreamingPipelineOutput.Complete(StreamingFinalResult.Pass());
    }

    private bool ShouldEvaluate(int totalChars, int charsSinceLastCheck, DateTime lastCheckTime, bool firstCheckDone)
    {
        // Haven't accumulated enough for the first check
        if (!firstCheckDone && totalChars < _options.MinCharsBeforeFirstCheck)
            return false;

        // Character interval
        if (charsSinceLastCheck >= _options.EvaluationIntervalChars)
            return true;

        // Time interval
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
        // If the rule explicitly declares its streaming mode, use it
        if (rule is IStreamingGuardrailRule streamingRule)
            return streamingRule.StreamingMode;

        // Default heuristic: LLM rules are FinalOnly, all others are EveryCheck
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

            // Check MinTokensBeforeFirstCheck
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
            var result = await rule.EvaluateAsync(context, cancellationToken);
            var taggedResult = result with { RuleName = rule.Name };
            results.Add(taggedResult);

            if (result.IsBlocked)
            {
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

    [LoggerMessage(Level = LogLevel.Warning, Message = "Progressive guardrail violation by '{RuleName}' after {YieldedChars} chars yielded — retracting")]
    private static partial void LogProgressiveViolation(ILogger logger, string ruleName, int yieldedChars);

    [LoggerMessage(Level = LogLevel.Information, Message = "Progressive guardrail modification after {YieldedChars} chars yielded — retracting and replacing")]
    private static partial void LogProgressiveModification(ILogger logger, int yieldedChars);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Final guardrail check violation by '{RuleName}' — retracting all yielded content")]
    private static partial void LogFinalViolation(ILogger logger, string ruleName);

    [LoggerMessage(Level = LogLevel.Information, Message = "Final guardrail check modified content — retracting and replacing")]
    private static partial void LogFinalModification(ILogger logger);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Running streaming guardrail rule '{RuleName}' ({Mode})")]
    private static partial void LogRunningRule(ILogger logger, string ruleName, string mode);
}
