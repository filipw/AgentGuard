using AgentGuard.Core.Abstractions;
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
            var result = await rule.EvaluateAsync(ruleContext, cancellationToken);
            var taggedResult = result with { RuleName = rule.Name };
            results.Add(taggedResult);

            if (result.IsBlocked)
            {
                LogRuleBlocked(_logger, rule.Name, result.Reason);
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
                LogRuleModified(_logger, rule.Name, result.Reason);
                currentText = result.ModifiedText;
            }
        }

        return new GuardrailPipelineResult
        {
            IsBlocked = false,
            AllResults = results,
            FinalText = currentText,
            WasModified = currentText != context.Text
        };
    }

    private async ValueTask<GuardrailPipelineResult> RunReaskLoopAsync(
        GuardrailContext originalContext,
        GuardrailPipelineResult blockedResult,
        ReaskOptions options,
        IChatClient chatClient,
        CancellationToken cancellationToken)
    {
        var currentBlockedResult = blockedResult;

        for (var attempt = 0; attempt < options.MaxAttempts; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var violationReason = currentBlockedResult.BlockingResult?.Reason ?? "Output was blocked by a guardrail.";
            LogReaskAttempt(_logger, attempt + 1, options.MaxAttempts, violationReason);

            var reaskMessages = BuildReaskMessages(originalContext, currentBlockedResult, options);
            var response = await chatClient.GetResponseAsync(reaskMessages, options.ChatOptions, cancellationToken);
            var newText = response.Text ?? "";

            var reaskContext = originalContext with { Text = newText };
            var reaskResult = await RunCoreAsync(reaskContext, cancellationToken);

            if (!reaskResult.IsBlocked)
            {
                LogReaskSuccess(_logger, attempt + 1);
                return reaskResult with
                {
                    WasReasked = true,
                    ReaskAttemptsUsed = attempt + 1
                };
            }

            currentBlockedResult = reaskResult;
        }

        LogReaskExhausted(_logger, options.MaxAttempts);
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

        // Include the original conversation context if available
        if (originalContext.Messages is { Count: > 0 } contextMessages)
        {
            messages.AddRange(contextMessages);
        }

        // Include the blocked response so the LLM knows what to avoid
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

    [LoggerMessage(Level = LogLevel.Warning, Message = "Guardrail rule '{RuleName}' BLOCKED: {Reason}")]
    private static partial void LogRuleBlocked(ILogger logger, string ruleName, string? reason);

    [LoggerMessage(Level = LogLevel.Information, Message = "Guardrail rule '{RuleName}' modified text: {Reason}")]
    private static partial void LogRuleModified(ILogger logger, string ruleName, string? reason);

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
