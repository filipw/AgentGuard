using Xunit;

// the telemetry tests listen to the process-wide "AgentGuard" activity source, which would also capture
// spans from test classes running in parallel, so this assembly's tests run one at a time
[assembly: CollectionBehavior(DisableTestParallelization = true)]
