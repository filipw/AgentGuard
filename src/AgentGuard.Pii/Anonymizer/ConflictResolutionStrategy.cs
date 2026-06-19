namespace AgentGuard.Pii.Anonymizer;

/// <summary>Strategy for resolving overlapping entities before anonymization.</summary>
public enum ConflictResolutionStrategy
{
    /// <summary>Merge similar or fully-contained entities, keeping the higher score.</summary>
    MergeSimilarOrContained,

    /// <summary>Additionally trim partially-overlapping entities so no spans intersect.</summary>
    RemoveIntersections,
}
