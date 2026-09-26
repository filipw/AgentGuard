using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Rules;
using AgentGuard.Core.Streaming;
using Microsoft.Extensions.AI;

namespace AgentGuard.Core.Guardrails;

/// <summary>
/// The default <see cref="IGuardrailPolicy"/>: an ordered, immutable set of rules plus the
/// violation handler and the optional streaming and re-ask configuration.
/// </summary>
/// <remarks>
/// Several rules own real resources - a pooled ONNX inference session (the Defender, PIGuard, Opir
/// and NER rules) or an <see cref="System.Net.Http.HttpClient"/> behind a remote PII detector.
/// Disposing the policy releases every rule that implements <see cref="IDisposable"/>, so a policy
/// that is rebuilt rather than held for the process lifetime does not leak them.
/// <see cref="IGuardrailPolicy"/> itself is deliberately not <see cref="IDisposable"/> - that would
/// break every existing implementation - so callers holding the interface should use
/// <c>(policy as IDisposable)?.Dispose()</c>.
/// </remarks>
public sealed class GuardrailPolicy : IGuardrailPolicy, IDisposable
{
    private readonly List<IGuardrailRule> _rules;

    /// <summary>Initializes a new instance of the <see cref="GuardrailPolicy"/> class.</summary>
    /// <param name="name">The policy name.</param>
    /// <param name="rules">The rules; they are sorted by <see cref="IGuardrailRule.Order"/>.</param>
    /// <param name="violationHandler">Produces the text shown on a block. Defaults to a generic refusal.</param>
    /// <param name="progressiveStreaming">Enables progressive streaming when non-null.</param>
    /// <param name="reaskOptions">Enables the output re-ask loop when non-null.</param>
    /// <param name="reaskChatClient">The client used for re-ask calls.</param>
    public GuardrailPolicy(
        string name,
        IEnumerable<IGuardrailRule> rules,
        IViolationHandler? violationHandler = null,
        ProgressiveStreamingOptions? progressiveStreaming = null,
        ReaskOptions? reaskOptions = null,
        IChatClient? reaskChatClient = null)
    {
        Name = name;
        _rules = rules.OrderBy(r => r.Order).ToList();
        ViolationHandler = violationHandler ?? new DefaultViolationHandler();
        ProgressiveStreaming = progressiveStreaming;
        ReaskOptions = reaskOptions;
        ReaskChatClient = reaskChatClient;
    }

    private bool _disposed;

    /// <inheritdoc />
    public string Name { get; }

    /// <inheritdoc />
    public IReadOnlyList<IGuardrailRule> Rules => _rules;

    /// <inheritdoc />
    public IViolationHandler ViolationHandler { get; }

    /// <summary>Disposes every rule in this policy that implements <see cref="IDisposable"/>.</summary>
    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;

        foreach (var rule in _rules)
        {
            // a rule that fails to release its own resources must not stop the rest from doing so
            try
            {
                // a gated rule holds the resource-owning rule inside it
                (rule.Unwrap() as IDisposable)?.Dispose();
            }
            catch (ObjectDisposedException)
            {
            }
        }
    }

    /// <summary>
    /// Progressive streaming options, if progressive streaming is enabled for this policy.
    /// When null, streaming uses the default buffer-then-release strategy.
    /// </summary>
    public ProgressiveStreamingOptions? ProgressiveStreaming { get; }

    /// <inheritdoc />
    public ReaskOptions? ReaskOptions { get; }

    /// <inheritdoc />
    public IChatClient? ReaskChatClient { get; }
}

/// <summary>Shows the blocking rule's own reason, falling back to a generic refusal.</summary>
public sealed class DefaultViolationHandler : IViolationHandler
{
    private readonly string _defaultMessage;

    /// <summary>Initializes a new instance of the <see cref="DefaultViolationHandler"/> class.</summary>
    /// <param name="defaultMessage">Used when the blocking result carries no reason.</param>
    public DefaultViolationHandler(string? defaultMessage = null)
    {
        _defaultMessage = defaultMessage ?? "I'm unable to process that request.";
    }

    /// <inheritdoc />
    public ValueTask<string> HandleViolationAsync(
        GuardrailResult result, GuardrailContext context, CancellationToken cancellationToken = default)
        => ValueTask.FromResult(result.Reason ?? _defaultMessage);
}

/// <summary>
/// Always shows the same message, whatever blocked. Use this when the reason must not leak which
/// rule fired.
/// </summary>
public sealed class MessageViolationHandler : IViolationHandler
{
    private readonly string _message;

    /// <summary>Initializes a new instance of the <see cref="MessageViolationHandler"/> class.</summary>
    /// <param name="message">The message to show on every violation.</param>
    public MessageViolationHandler(string message) => _message = message;

    /// <inheritdoc />
    public ValueTask<string> HandleViolationAsync(
        GuardrailResult result, GuardrailContext context, CancellationToken cancellationToken = default)
        => ValueTask.FromResult(_message);
}

/// <summary>Builds the violation message with a caller-supplied delegate.</summary>
public sealed class DelegateViolationHandler : IViolationHandler
{
    private readonly Func<GuardrailResult, GuardrailContext, CancellationToken, ValueTask<string>> _handler;

    /// <summary>Initializes a new instance of the <see cref="DelegateViolationHandler"/> class.</summary>
    /// <param name="handler">Produces the message from the blocking result and context.</param>
    public DelegateViolationHandler(Func<GuardrailResult, GuardrailContext, CancellationToken, ValueTask<string>> handler)
        => _handler = handler;

    /// <inheritdoc />
    public ValueTask<string> HandleViolationAsync(
        GuardrailResult result, GuardrailContext context, CancellationToken cancellationToken = default)
        => _handler(result, context, cancellationToken);
}
