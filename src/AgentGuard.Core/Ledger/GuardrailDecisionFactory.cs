using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Telemetry;

namespace AgentGuard.Core.Ledger;

/// <summary>
/// Builds <see cref="GuardrailDecision"/> instances from pipeline evaluation state.
/// Shared by the buffered and streaming pipelines so both record decisions identically.
/// </summary>
internal static class GuardrailDecisionFactory
{
    public static GuardrailDecision Create(
        string policyName,
        GuardrailContext context,
        string outputText,
        IReadOnlyList<GuardrailResult> results,
        string outcome,
        GuardrailResult? blockingResult,
        bool wasModified)
    {
        var captureContent = AgentGuardTelemetry.EnableSensitiveData;

        var ruleOutcomes = new List<RuleOutcome>(results.Count);
        foreach (var r in results)
        {
            var ruleOutcome = r.IsBlocked ? AgentGuardTelemetry.Outcomes.Blocked
                : r.IsModified ? AgentGuardTelemetry.Outcomes.Modified
                : r.IsError ? AgentGuardTelemetry.Outcomes.Error
                : AgentGuardTelemetry.Outcomes.Passed;
            ruleOutcomes.Add(new RuleOutcome(r.RuleName, ruleOutcome));
        }

        return new GuardrailDecision
        {
            PolicyName = policyName,
            Phase = context.Phase,
            AgentName = context.AgentName,
            Outcome = outcome,
            BlockingRuleName = blockingResult?.RuleName,
            Severity = blockingResult?.Severity ?? GuardrailSeverity.None,
            BlockReason = blockingResult?.Reason,
            RuleOutcomes = ruleOutcomes,
            WasModified = wasModified,
            InputHash = HashChainLedger.HashText(context.Text),
            OutputHash = HashChainLedger.HashText(outputText),
            Input = captureContent ? context.Text : null,
            Output = captureContent ? outputText : null,
            Timestamp = DateTimeOffset.UtcNow
        };
    }
}
