namespace AgentGuard.Pii.Structured;

/// <summary>
/// Restricts which JSON string values <see cref="StructuredEngine"/> analyzes, by dotted key path.
/// A path is the dot-joined chain of property names from the root; array elements do not add a
/// segment, so every element of <c>tags</c> shares the path <c>tags</c> and a nested
/// <c>user.email</c> is addressed as <c>user.email</c>.
/// </summary>
public sealed class JsonRedactionScope
{
    /// <summary>
    /// When set, only string values whose path is in this list are analyzed (an allowlist). When
    /// null, all string values are analyzed except those excluded by <see cref="ExcludePaths"/>.
    /// </summary>
    public IReadOnlyList<string>? IncludePaths { get; init; }

    /// <summary>String values whose path is in this list are left untouched (a denylist).</summary>
    public IReadOnlyList<string>? ExcludePaths { get; init; }

    /// <summary>Returns <c>true</c> if a string value at <paramref name="path"/> should be analyzed.</summary>
    internal bool ShouldAnalyze(string path)
    {
        if (ExcludePaths is { Count: > 0 } && ExcludePaths.Contains(path, StringComparer.Ordinal))
            return false;

        if (IncludePaths is { Count: > 0 })
            return IncludePaths.Contains(path, StringComparer.Ordinal);

        return true;
    }
}
