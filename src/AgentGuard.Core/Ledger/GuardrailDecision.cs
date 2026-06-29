using AgentGuard.Core.Abstractions;

namespace AgentGuard.Core.Ledger;

/// <summary>
/// A single per-rule outcome captured for the decision ledger.
/// </summary>
/// <param name="RuleName">The name of the rule.</param>
/// <param name="Outcome">The outcome value (passed / blocked / modified / error).</param>
public readonly record struct RuleOutcome(string RuleName, string Outcome);

/// <summary>
/// The immutable facts about a single guardrail pipeline decision, recorded into an
/// <see cref="IGuardrailLedger"/>. Raw <see cref="Input"/>/<see cref="Output"/> text is
/// populated only when content capture is enabled (see
/// <see cref="Telemetry.AgentGuardTelemetry.EnableSensitiveData"/>); otherwise only the
/// privacy-preserving <see cref="InputHash"/>/<see cref="OutputHash"/> are present.
/// </summary>
public sealed record GuardrailDecision
{
    /// <summary>The name of the policy that produced this decision.</summary>
    public required string PolicyName { get; init; }

    /// <summary>The phase the pipeline ran in.</summary>
    public required GuardrailPhase Phase { get; init; }

    /// <summary>The agent name, if available.</summary>
    public string? AgentName { get; init; }

    /// <summary>The overall outcome (passed / blocked / modified). Uses
    /// <see cref="Telemetry.AgentGuardTelemetry.Outcomes"/> values.</summary>
    public required string Outcome { get; init; }

    /// <summary>The name of the rule that blocked, when <see cref="Outcome"/> is blocked.</summary>
    public string? BlockingRuleName { get; init; }

    /// <summary>The severity of the blocking result, when blocked.</summary>
    public GuardrailSeverity Severity { get; init; } = GuardrailSeverity.None;

    /// <summary>The reason the pipeline blocked, when blocked.</summary>
    public string? BlockReason { get; init; }

    /// <summary>Per-rule outcomes evaluated in this decision, in execution order.</summary>
    public IReadOnlyList<RuleOutcome> RuleOutcomes { get; init; } = [];

    /// <summary>Whether the text was modified by at least one rule.</summary>
    public bool WasModified { get; init; }

    /// <summary>SHA-256 (hex) of the input text. Always present.</summary>
    public required string InputHash { get; init; }

    /// <summary>SHA-256 (hex) of the final/output text. Always present.</summary>
    public required string OutputHash { get; init; }

    /// <summary>Raw input text. Populated only when content capture is enabled.</summary>
    public string? Input { get; init; }

    /// <summary>Raw output text. Populated only when content capture is enabled.</summary>
    public string? Output { get; init; }

    /// <summary>UTC timestamp of when the decision was made.</summary>
    public required DateTimeOffset Timestamp { get; init; }
}
