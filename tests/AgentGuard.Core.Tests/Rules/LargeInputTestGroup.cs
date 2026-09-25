using Xunit;

namespace AgentGuard.Core.Tests.Rules;

/// <summary>
/// Tests that deliberately scan large, adversarially padded inputs or burn through a regex match
/// timeout.
/// </summary>
/// <remarks>
/// Parallelization is disabled, so xunit runs this collection on its own after the parallel ones.
/// That keeps the time budgets these tests assert on meaningful on a loaded machine, and keeps their
/// CPU load from skewing timing-sensitive tests elsewhere - the span-capturing telemetry tests read
/// the most recent span from a process-wide listener and misread it under contention.
/// </remarks>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class LargeInputTestGroup
{
    /// <summary>The collection name.</summary>
    public const string Name = "Large inputs";
}
