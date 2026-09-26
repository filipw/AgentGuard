using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Guardrails;
using AgentGuard.Core.Telemetry;
using Microsoft.Agents.AI;
using Microsoft.Agents.AI.Workflows;
using Microsoft.Agents.AI.Workflows.Checkpointing;
using Microsoft.Extensions.AI;

namespace AgentGuard.AgentFramework.Workflows;

/// <summary>
/// Wraps a void-return executor with input guardrails.
/// If a guardrail blocks, a <see cref="GuardrailViolationException"/> is thrown and the inner executor does not run.
/// If a guardrail rewrites the text, the rewritten message is passed to the inner executor.
/// </summary>
/// <remarks>
/// <para>
/// The guarded executor has the id <c>guarded-{inner id}</c> and takes the inner executor's place in the workflow.
/// It declares the inner executor's protocol - the message types it handles, sends and yields - and uses its
/// <see cref="ExecutorOptions"/> and cross-run sharing, so whatever the inner executor sends or yields through the
/// <see cref="IWorkflowContext"/> goes through as it would without the guard. It forwards the inner executor's
/// lifecycle: initialization, the message delivery hooks, checkpoint save and restore,
/// <see cref="IResettableExecutor.ResetAsync"/> (it is resettable exactly when the inner executor is) and disposal.
/// </para>
/// <para>
/// Chat messages are guarded as chat. A <see cref="ChatMessage"/> has its text checked, and a rewrite replaces only
/// that text: attachments and other non-text content, the role, author, message id, timestamp and additional
/// properties stay.
/// A message collection (<see cref="List{T}"/> or array of <see cref="ChatMessage"/>, or an interface a list
/// implements) or an <see cref="AgentResponse"/> is guarded like a request to an agent (see
/// <see cref="ChatMessageGuard.GuardInputAsync"/>): every user message is checked, an earlier one the policy blocks is
/// replaced with <see cref="ChatMessageGuard.RemovedMessagePlaceholder"/>, and a block of the newest one blocks. The
/// newest message with text is checked whatever its role, since an executor's input is often another agent's
/// response. The rewritten messages arrive in the collection type the executor declares.
/// </para>
/// <para>
/// Any other message goes through the configured <see cref="ITextExtractor"/>. A rewrite is applied to
/// <see cref="string"/> messages and to any type the extractor rebuilds (<see cref="ITextExtractor.TryRebuild"/>);
/// otherwise the original message goes on and a warning is logged.
/// </para>
/// <para>
/// Messages of the other types the inner executor handles are guarded the same way, then handed to it through
/// <see cref="Executor.ExecuteCoreAsync(object, TypeId, IWorkflowContext, CancellationToken)"/>, which routes them to
/// its own handlers.
/// </para>
/// </remarks>
/// <typeparam name="TInput">The type of message the inner executor handles.</typeparam>
public class GuardedExecutor<TInput> : Executor<TInput>, IAsyncDisposable
{
    private const string InputSpan = AgentGuardTelemetry.Spans.ExecutorGuard;

    private readonly ExecutorGuard _guard;

    internal GuardedExecutor(
        Executor<TInput> inner,
        IGuardrailPolicy policy,
        GuardedExecutorOptions? options = null)
        : base($"guarded-{inner.Id}", InnerExecutor.GetOptions(inner), InnerExecutor.IsCrossRunShareable(inner))
    {
        Inner = inner;
        _guard = new ExecutorGuard(inner.Id, policy, options);
    }

    internal Executor<TInput> Inner { get; }

    internal static GuardedExecutor<TInput> Create(
        Executor<TInput> inner, IGuardrailPolicy policy, GuardedExecutorOptions? options) =>
        inner is IResettableExecutor
            ? new ResettableGuardedExecutor<TInput>(inner, policy, options)
            : new GuardedExecutor<TInput>(inner, policy, options);

    /// <inheritdoc />
    public override async ValueTask HandleAsync(TInput message, IWorkflowContext context, CancellationToken cancellationToken = default)
    {
        var guarded = await _guard.GuardAsync(message, typeof(TInput), GuardrailPhase.Input, InputSpan, cancellationToken)
            .ConfigureAwait(false);

        await Inner.HandleAsync((TInput)guarded!, context, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    protected override ProtocolBuilder ConfigureProtocol(ProtocolBuilder protocolBuilder) =>
        InnerExecutor.MirrorProtocol(base.ConfigureProtocol(protocolBuilder), Inner, typeof(TInput), ForwardAsync);

    /// <inheritdoc />
    protected override ValueTask InitializeAsync(IWorkflowContext context, CancellationToken cancellationToken = default) =>
        InnerExecutor.InitializeAsync(Inner, context, cancellationToken);

    /// <inheritdoc />
    protected override ValueTask OnMessageDeliveryStartingAsync(IWorkflowContext context, CancellationToken cancellationToken = default) =>
        InnerExecutor.OnMessageDeliveryStartingAsync(Inner, context, cancellationToken);

    /// <inheritdoc />
    protected override ValueTask OnMessageDeliveryFinishedAsync(IWorkflowContext context, CancellationToken cancellationToken = default) =>
        InnerExecutor.OnMessageDeliveryFinishedAsync(Inner, context, cancellationToken);

    /// <inheritdoc />
    protected override ValueTask OnCheckpointingAsync(IWorkflowContext context, CancellationToken cancellationToken = default) =>
        InnerExecutor.OnCheckpointingAsync(Inner, context, cancellationToken);

    /// <inheritdoc />
    protected override ValueTask OnCheckpointRestoredAsync(IWorkflowContext context, CancellationToken cancellationToken = default) =>
        InnerExecutor.OnCheckpointRestoredAsync(Inner, context, cancellationToken);

    /// <summary>
    /// Disposes the inner executor when it is disposable - the workflow runtime disposes a run's executors when
    /// the run ends. The guardrail policy is not disposed, since a reused workflow runs this executor again.
    /// </summary>
    /// <returns>A task that completes when the inner executor is disposed.</returns>
    public async ValueTask DisposeAsync()
    {
        await InnerExecutor.DisposeAsync(Inner).ConfigureAwait(false);
        GC.SuppressFinalize(this);
    }

    private ValueTask ForwardAsync(object message, Type? handledType, IWorkflowContext context, CancellationToken cancellationToken) =>
        _guard.ForwardAsync(Inner, message, handledType, InputSpan, context, cancellationToken);
}

/// <summary>
/// Wraps a typed-return executor with input and output guardrails.
/// If a guardrail blocks on either side, a <see cref="GuardrailViolationException"/> is thrown.
/// If a guardrail rewrites the text, the rewritten input is passed to the inner executor, and the rewritten
/// result is what the executor returns.
/// </summary>
/// <remarks>
/// <para>
/// The guarded executor has the id <c>guarded-{inner id}</c> and takes the inner executor's place in the workflow.
/// It declares the inner executor's protocol - the message types it handles, sends and yields - and uses its
/// <see cref="ExecutorOptions"/> and cross-run sharing, so whatever the inner executor sends or yields through the
/// <see cref="IWorkflowContext"/> goes through as it would without the guard, and the guarded result is sent and
/// yielded as the inner executor's options specify. It forwards the inner executor's lifecycle: initialization,
/// the message delivery hooks, checkpoint save and restore, <see cref="IResettableExecutor.ResetAsync"/> (it is
/// resettable exactly when the inner executor is) and disposal.
/// </para>
/// <para>
/// Chat messages are guarded as chat. A <see cref="ChatMessage"/> has its text checked, and a rewrite replaces only
/// that text: attachments and other non-text content, the role, author, message id, timestamp and additional
/// properties stay.
/// On the way in, a message collection (<see cref="List{T}"/> or array of <see cref="ChatMessage"/>, or an interface
/// a list implements) or an <see cref="AgentResponse"/> is guarded like a request to an agent (see
/// <see cref="ChatMessageGuard.GuardInputAsync"/>): every user message is checked, an earlier one the policy blocks
/// is replaced with <see cref="ChatMessageGuard.RemovedMessagePlaceholder"/>, and a block of the newest one blocks.
/// On the way out, one is guarded like an agent's response (see <see cref="ChatMessageGuard.GuardOutputAsync"/>):
/// its assistant messages, their reasoning, and its tool calls and results. Either way the newest message with
/// text is checked whatever its role, since an executor's input is often another agent's response and its result
/// a prompt for the next one. The rewritten messages come back in the type the executor declares; an
/// <see cref="AgentResponse"/> keeps its ids, timestamp, usage, finish reason, continuation token and additional
/// properties.
/// </para>
/// <para>
/// Any other value goes through the configured <see cref="ITextExtractor"/>. A rewrite is applied to
/// <see cref="string"/> values and to any type the extractor rebuilds (<see cref="ITextExtractor.TryRebuild"/>);
/// otherwise the original value goes on and a warning is logged.
/// </para>
/// <para>
/// Messages of the other types the inner executor handles are guarded on input, then handed to it through
/// <see cref="Executor.ExecuteCoreAsync(object, TypeId, IWorkflowContext, CancellationToken)"/>, which routes them to
/// its own handlers and sends or yields their results itself, without an output check.
/// </para>
/// </remarks>
/// <typeparam name="TInput">The type of message the inner executor handles.</typeparam>
/// <typeparam name="TOutput">The type of result the inner executor returns.</typeparam>
public class GuardedExecutor<TInput, TOutput> : Executor<TInput, TOutput>, IAsyncDisposable
{
    private const string InputSpan = AgentGuardTelemetry.Spans.ExecutorGuard + " input";
    private const string OutputSpan = AgentGuardTelemetry.Spans.ExecutorGuard + " output";

    private readonly ExecutorGuard _guard;

    internal GuardedExecutor(
        Executor<TInput, TOutput> inner,
        IGuardrailPolicy policy,
        GuardedExecutorOptions? options = null)
        : base($"guarded-{inner.Id}", InnerExecutor.GetOptions(inner), InnerExecutor.IsCrossRunShareable(inner))
    {
        Inner = inner;
        _guard = new ExecutorGuard(inner.Id, policy, options);
    }

    internal Executor<TInput, TOutput> Inner { get; }

    internal static GuardedExecutor<TInput, TOutput> Create(
        Executor<TInput, TOutput> inner, IGuardrailPolicy policy, GuardedExecutorOptions? options) =>
        inner is IResettableExecutor
            ? new ResettableGuardedExecutor<TInput, TOutput>(inner, policy, options)
            : new GuardedExecutor<TInput, TOutput>(inner, policy, options);

    /// <inheritdoc />
    public override async ValueTask<TOutput> HandleAsync(TInput message, IWorkflowContext context, CancellationToken cancellationToken = default)
    {
        var input = await _guard.GuardAsync(message, typeof(TInput), GuardrailPhase.Input, InputSpan, cancellationToken)
            .ConfigureAwait(false);

        var output = await Inner.HandleAsync((TInput)input!, context, cancellationToken).ConfigureAwait(false);

        var guarded = await _guard.GuardAsync(output, typeof(TOutput), GuardrailPhase.Output, OutputSpan, cancellationToken)
            .ConfigureAwait(false);

        return (TOutput)guarded!;
    }

    /// <inheritdoc />
    protected override ProtocolBuilder ConfigureProtocol(ProtocolBuilder protocolBuilder) =>
        InnerExecutor.MirrorProtocol(base.ConfigureProtocol(protocolBuilder), Inner, typeof(TInput), ForwardAsync);

    /// <inheritdoc />
    protected override ValueTask InitializeAsync(IWorkflowContext context, CancellationToken cancellationToken = default) =>
        InnerExecutor.InitializeAsync(Inner, context, cancellationToken);

    /// <inheritdoc />
    protected override ValueTask OnMessageDeliveryStartingAsync(IWorkflowContext context, CancellationToken cancellationToken = default) =>
        InnerExecutor.OnMessageDeliveryStartingAsync(Inner, context, cancellationToken);

    /// <inheritdoc />
    protected override ValueTask OnMessageDeliveryFinishedAsync(IWorkflowContext context, CancellationToken cancellationToken = default) =>
        InnerExecutor.OnMessageDeliveryFinishedAsync(Inner, context, cancellationToken);

    /// <inheritdoc />
    protected override ValueTask OnCheckpointingAsync(IWorkflowContext context, CancellationToken cancellationToken = default) =>
        InnerExecutor.OnCheckpointingAsync(Inner, context, cancellationToken);

    /// <inheritdoc />
    protected override ValueTask OnCheckpointRestoredAsync(IWorkflowContext context, CancellationToken cancellationToken = default) =>
        InnerExecutor.OnCheckpointRestoredAsync(Inner, context, cancellationToken);

    /// <summary>
    /// Disposes the inner executor when it is disposable - the workflow runtime disposes a run's executors when
    /// the run ends. The guardrail policy is not disposed, since a reused workflow runs this executor again.
    /// </summary>
    /// <returns>A task that completes when the inner executor is disposed.</returns>
    public async ValueTask DisposeAsync()
    {
        await InnerExecutor.DisposeAsync(Inner).ConfigureAwait(false);
        GC.SuppressFinalize(this);
    }

    private ValueTask ForwardAsync(object message, Type? handledType, IWorkflowContext context, CancellationToken cancellationToken) =>
        _guard.ForwardAsync(Inner, message, handledType, InputSpan, context, cancellationToken);
}

/// <summary>A <see cref="GuardedExecutor{TInput}"/> whose inner executor can be reset between runs.</summary>
internal sealed class ResettableGuardedExecutor<TInput>(
    Executor<TInput> inner, IGuardrailPolicy policy, GuardedExecutorOptions? options)
    : GuardedExecutor<TInput>(inner, policy, options), IResettableExecutor
{
    public ValueTask ResetAsync() => ((IResettableExecutor)Inner).ResetAsync();
}

/// <summary>A <see cref="GuardedExecutor{TInput, TOutput}"/> whose inner executor can be reset between runs.</summary>
internal sealed class ResettableGuardedExecutor<TInput, TOutput>(
    Executor<TInput, TOutput> inner, IGuardrailPolicy policy, GuardedExecutorOptions? options)
    : GuardedExecutor<TInput, TOutput>(inner, policy, options), IResettableExecutor
{
    public ValueTask ResetAsync() => ((IResettableExecutor)Inner).ResetAsync();
}
