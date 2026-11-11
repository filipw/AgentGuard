using Microsoft.Agents.AI.Workflows;

namespace AgentGuard.AgentFramework.Workflows;

/// <summary>
/// The <see cref="IWorkflowContext"/> a guarded executor hands to the executor it wraps. Every message the
/// inner executor sends (<see cref="SendMessageAsync"/>) or yields (<see cref="YieldOutputAsync"/>) goes
/// through the output guardrails first: a blocked message is not forwarded and the call throws
/// <see cref="GuardrailViolationException"/>, a rewritten message is forwarded in its rewritten form. A rewrite
/// that can't be applied to the message is handled as it is for a handler's result: the message is blocked,
/// unless <see cref="GuardedExecutorOptions.AllowUnappliedModifications"/> lets the original through.
/// </summary>
/// <remarks>
/// <para>
/// Every other member delegates to the workflow's own context unchanged, the overloads the interface
/// implements by default included, so state stays in the guarded executor's scope and halt requests and
/// trace context behave as they do without the guard.
/// </para>
/// <para>
/// Events (<see cref="AddEventAsync"/>) are not guarded. They report progress to whoever runs the workflow
/// and are never delivered to another executor as a message or yielded as workflow output, so an executor
/// that puts model- or user-facing text in a custom event has to guard it itself. The one exception is the
/// <see cref="ExecutorCompletedEvent"/> the inner executor raises when it routes a message to one of its
/// other handlers: it carries the handler's result, which is guarded there, so the event reports the result
/// in the form that is then sent and yielded, and a blocked result is not reported at all.
/// </para>
/// </remarks>
internal sealed class GuardedWorkflowContext(IWorkflowContext inner, ExecutorGuard guard) : IWorkflowContext
{
    // a handler's result, as the inner executor's own routing reported it, and what the guard made of it;
    // the routing sends and yields that same result next, and those get the verdict already reached
    private object? _result;
    private object? _guardedResult;

    /// <inheritdoc />
    public IReadOnlyDictionary<string, string>? TraceContext => inner.TraceContext;

    /// <inheritdoc />
    public bool ConcurrentRunsEnabled => inner.ConcurrentRunsEnabled;

    /// <inheritdoc />
    public ValueTask AddEventAsync(WorkflowEvent workflowEvent, CancellationToken cancellationToken = default) =>
        workflowEvent is ExecutorCompletedEvent { Data: not null } completed
        && string.Equals(completed.ExecutorId, guard.ExecutorId, StringComparison.Ordinal)
            ? AddCompletedEventAsync(completed, cancellationToken)
            : inner.AddEventAsync(workflowEvent, cancellationToken);

    /// <inheritdoc />
    public async ValueTask SendMessageAsync(object message, string? targetId, CancellationToken cancellationToken = default) =>
        await inner.SendMessageAsync(await GuardAsync(message, cancellationToken).ConfigureAwait(false), targetId, cancellationToken)
            .ConfigureAwait(false);

    /// <inheritdoc />
    public async ValueTask YieldOutputAsync(object output, CancellationToken cancellationToken = default) =>
        await inner.YieldOutputAsync(await GuardAsync(output, cancellationToken).ConfigureAwait(false), cancellationToken)
            .ConfigureAwait(false);

    /// <inheritdoc />
    public ValueTask RequestHaltAsync() => inner.RequestHaltAsync();

    /// <inheritdoc />
    public ValueTask<T?> ReadStateAsync<T>(string key, string? scopeName = null, CancellationToken cancellationToken = default) =>
        inner.ReadStateAsync<T>(key, scopeName, cancellationToken);

    /// <inheritdoc />
    public ValueTask<T?> ReadStateAsync<T>(string key, CancellationToken cancellationToken) =>
        inner.ReadStateAsync<T>(key, cancellationToken);

    /// <inheritdoc />
    public ValueTask<T> ReadOrInitStateAsync<T>(
        string key, Func<T> initialStateFactory, string? scopeName = null, CancellationToken cancellationToken = default) =>
        inner.ReadOrInitStateAsync(key, initialStateFactory, scopeName, cancellationToken);

    /// <inheritdoc />
    public ValueTask<T> ReadOrInitStateAsync<T>(string key, Func<T> initialStateFactory, CancellationToken cancellationToken) =>
        inner.ReadOrInitStateAsync(key, initialStateFactory, cancellationToken);

    /// <inheritdoc />
    public ValueTask<HashSet<string>> ReadStateKeysAsync(string? scopeName = null, CancellationToken cancellationToken = default) =>
        inner.ReadStateKeysAsync(scopeName, cancellationToken);

    /// <inheritdoc />
    public ValueTask QueueStateUpdateAsync<T>(string key, T? value, string? scopeName = null, CancellationToken cancellationToken = default) =>
        inner.QueueStateUpdateAsync(key, value, scopeName, cancellationToken);

    /// <inheritdoc />
    public ValueTask QueueStateUpdateAsync<T>(string key, T? value, CancellationToken cancellationToken) =>
        inner.QueueStateUpdateAsync(key, value, cancellationToken);

    /// <inheritdoc />
    public ValueTask QueueClearScopeAsync(string? scopeName = null, CancellationToken cancellationToken = default) =>
        inner.QueueClearScopeAsync(scopeName, cancellationToken);

    /// <inheritdoc />
    public ValueTask QueueClearScopeAsync(CancellationToken cancellationToken) =>
        inner.QueueClearScopeAsync(cancellationToken);

    private async ValueTask AddCompletedEventAsync(ExecutorCompletedEvent completed, CancellationToken cancellationToken)
    {
        var result = completed.Data!;
        var guarded = await guard.GuardEmissionAsync(result, cancellationToken).ConfigureAwait(false);

        _result = result;
        _guardedResult = guarded;

        await inner.AddEventAsync(
            ReferenceEquals(guarded, result) ? completed : new ExecutorCompletedEvent(completed.ExecutorId, guarded),
            cancellationToken).ConfigureAwait(false);
    }

    private ValueTask<object> GuardAsync(object message, CancellationToken cancellationToken) =>
        _result is not null && ReferenceEquals(message, _result)
            ? ValueTask.FromResult(_guardedResult!)
            : guard.GuardEmissionAsync(message, cancellationToken);
}
