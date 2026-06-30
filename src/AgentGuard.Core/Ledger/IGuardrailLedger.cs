namespace AgentGuard.Core.Ledger;

/// <summary>
/// An append-only sink for guardrail pipeline decisions. Implementations own chain
/// stamping (sequence number, previous-hash linkage, and the entry hash); callers
/// supply only the decision facts via <see cref="Append"/>.
/// </summary>
public interface IGuardrailLedger
{
    /// <summary>
    /// Appends a decision to the ledger. The implementation computes the entry's
    /// sequence number, previous-hash linkage, and hash.
    /// </summary>
    /// <param name="decision">The decision facts to record.</param>
    void Append(GuardrailDecision decision);
}
