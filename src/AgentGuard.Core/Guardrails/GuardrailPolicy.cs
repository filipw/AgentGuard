using AgentGuard.Core.Abstractions;

namespace AgentGuard.Core.Guardrails;

public sealed class GuardrailPolicy : IGuardrailPolicy
{
    private readonly List<IGuardrailRule> _rules;

    public GuardrailPolicy(string name, IEnumerable<IGuardrailRule> rules, IViolationHandler? violationHandler = null)
    {
        Name = name;
        _rules = rules.OrderBy(r => r.Order).ToList();
        ViolationHandler = violationHandler ?? new DefaultViolationHandler();
    }

    public string Name { get; }
    public IReadOnlyList<IGuardrailRule> Rules => _rules;
    public IViolationHandler ViolationHandler { get; }
}

public sealed class DefaultViolationHandler : IViolationHandler
{
    private readonly string _defaultMessage;

    public DefaultViolationHandler(string? defaultMessage = null)
    {
        _defaultMessage = defaultMessage ?? "I'm unable to process that request.";
    }

    public ValueTask<string> HandleViolationAsync(
        GuardrailResult result, GuardrailContext context, CancellationToken cancellationToken = default)
        => ValueTask.FromResult(result.Reason ?? _defaultMessage);
}

public sealed class MessageViolationHandler : IViolationHandler
{
    private readonly string _message;
    public MessageViolationHandler(string message) => _message = message;

    public ValueTask<string> HandleViolationAsync(
        GuardrailResult result, GuardrailContext context, CancellationToken cancellationToken = default)
        => ValueTask.FromResult(_message);
}

public sealed class DelegateViolationHandler : IViolationHandler
{
    private readonly Func<GuardrailResult, GuardrailContext, CancellationToken, ValueTask<string>> _handler;
    public DelegateViolationHandler(Func<GuardrailResult, GuardrailContext, CancellationToken, ValueTask<string>> handler)
        => _handler = handler;

    public ValueTask<string> HandleViolationAsync(
        GuardrailResult result, GuardrailContext context, CancellationToken cancellationToken = default)
        => _handler(result, context, cancellationToken);
}
