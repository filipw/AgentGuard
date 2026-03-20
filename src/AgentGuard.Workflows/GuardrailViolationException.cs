using AgentGuard.Core.Abstractions;

namespace AgentGuard.Workflows;

/// <summary>
/// Thrown when a guardrail blocks execution within a workflow executor.
/// The MAF workflow runtime surfaces this as an ExecutorFailedEvent / WorkflowErrorEvent.
/// </summary>
public sealed class GuardrailViolationException : Exception
{
    /// <summary>
    /// The guardrail result that caused the block.
    /// </summary>
    public GuardrailResult ViolationResult { get; }

    /// <summary>
    /// Whether the violation occurred on input or output.
    /// </summary>
    public GuardrailPhase Phase { get; }

    /// <summary>
    /// The ID of the executor where the violation occurred.
    /// </summary>
    public string ExecutorId { get; }

    public GuardrailViolationException(GuardrailResult violationResult, GuardrailPhase phase, string executorId)
        : base($"Guardrail violation in executor '{executorId}' ({phase}): {violationResult.Reason}")
    {
        ViolationResult = violationResult;
        Phase = phase;
        ExecutorId = executorId;
    }
}
