using Microsoft.Extensions.Logging;

namespace AgentGuard.AgentFramework.Workflows;

/// <summary>
/// Options for configuring a <see cref="GuardedExecutor{TInput}"/> or <see cref="GuardedExecutor{TInput, TOutput}"/>.
/// </summary>
public sealed class GuardedExecutorOptions
{
    /// <summary>
    /// Custom text extractor for converting typed messages to strings for guardrail evaluation.
    /// If null, <see cref="DefaultTextExtractor.Instance"/> is used.
    /// </summary>
    public ITextExtractor? TextExtractor { get; set; }

    /// <summary>
    /// Logger for the guardrail pipeline. If null, a null logger is used.
    /// </summary>
    public ILogger? Logger { get; set; }
}
