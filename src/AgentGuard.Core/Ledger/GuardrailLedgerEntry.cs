namespace AgentGuard.Core.Ledger;

/// <summary>
/// A sealed record in the tamper-evident decision ledger. Wraps a
/// <see cref="GuardrailDecision"/> with its position in the hash chain
/// (<see cref="Seq"/>), the hash of the preceding entry (<see cref="PreviousHash"/>),
/// and this entry's own hash (<see cref="Hash"/>). The genesis entry has an empty
/// <see cref="PreviousHash"/>.
/// </summary>
public sealed record GuardrailLedgerEntry
{
    /// <summary>Zero-based sequence number of this entry in the chain.</summary>
    public required long Seq { get; init; }

    /// <summary>SHA-256 (hex) of the previous entry, or empty for the genesis entry.</summary>
    public required string PreviousHash { get; init; }

    /// <summary>SHA-256 (hex) of this entry, computed over its canonical serialization.</summary>
    public required string Hash { get; init; }

    /// <summary>The decision facts recorded in this entry.</summary>
    public required GuardrailDecision Decision { get; init; }
}
