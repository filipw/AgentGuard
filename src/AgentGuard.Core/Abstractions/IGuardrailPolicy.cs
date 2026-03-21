using AgentGuard.Core.Streaming;

namespace AgentGuard.Core.Abstractions;

public interface IGuardrailPolicy
{
    string Name { get; }
    IReadOnlyList<IGuardrailRule> Rules { get; }
    IViolationHandler ViolationHandler { get; }

    /// <summary>
    /// Progressive streaming options, if progressive streaming is enabled for this policy.
    /// When null, streaming uses the default buffer-then-release strategy.
    /// </summary>
    ProgressiveStreamingOptions? ProgressiveStreaming => null;
}

public interface IViolationHandler
{
    ValueTask<string> HandleViolationAsync(
        GuardrailResult result,
        GuardrailContext context,
        CancellationToken cancellationToken = default);
}

public interface IAgentGuardFactory
{
    IGuardrailPolicy GetPolicy(string name);
    IGuardrailPolicy GetDefaultPolicy();
}
