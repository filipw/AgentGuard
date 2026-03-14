using AgentGuard.Core.Abstractions;
using Microsoft.Extensions.Logging;

namespace AgentGuard.Core.Guardrails;

public sealed class GuardrailPipeline
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
        var results = new List<GuardrailResult>();
        var currentText = context.Text;

        var phaseRules = _policy.Rules
            .Where(r => r.Phase.HasFlag(context.Phase))
            .OrderBy(r => r.Order);

        foreach (var rule in phaseRules)
        {
            cancellationToken.ThrowIfCancellationRequested();

            _logger.LogDebug("Running guardrail rule '{RuleName}' in phase {Phase}", rule.Name, context.Phase);

            var ruleContext = context with { Text = currentText };
            var result = await rule.EvaluateAsync(ruleContext, cancellationToken);
            var taggedResult = result with { RuleName = rule.Name };
            results.Add(taggedResult);

            if (result.IsBlocked)
            {
                _logger.LogWarning("Guardrail rule '{RuleName}' BLOCKED: {Reason}", rule.Name, result.Reason);
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
                _logger.LogInformation("Guardrail rule '{RuleName}' modified text: {Reason}", rule.Name, result.Reason);
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
}

public sealed record GuardrailPipelineResult
{
    public required bool IsBlocked { get; init; }
    public bool WasModified { get; init; }
    public GuardrailResult? BlockingResult { get; init; }
    public required IReadOnlyList<GuardrailResult> AllResults { get; init; }
    public required string FinalText { get; init; }
}
