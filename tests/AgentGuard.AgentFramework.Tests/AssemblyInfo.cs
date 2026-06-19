using Xunit;

// telemetry tests register a process-global ActivitySource listener for the "AgentGuard" source,
// which would otherwise capture spans emitted by sibling test classes running in parallel and make
// span assertions non-deterministic. serialize this assembly's tests to keep them isolated.
[assembly: CollectionBehavior(DisableTestParallelization = true)]
