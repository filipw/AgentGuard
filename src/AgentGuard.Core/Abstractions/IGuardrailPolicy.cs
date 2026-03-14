namespace AgentGuard.Core.Abstractions;

public interface IGuardrailPolicy
{
    string Name { get; }
    IReadOnlyList<IGuardrailRule> Rules { get; }
    IViolationHandler ViolationHandler { get; }
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
