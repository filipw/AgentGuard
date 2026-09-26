using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.ExceptionServices;
using Microsoft.Agents.AI.Workflows;
using Microsoft.Agents.AI.Workflows.Checkpointing;

namespace AgentGuard.AgentFramework.Workflows;

/// <summary>
/// What a guarded executor needs to stand in for the executor it wraps: the inner executor's options,
/// sharing and protocol, its lifecycle hooks, and a way to hand it messages of the types the guarded
/// executor has no handler of its own for.
/// </summary>
/// <remarks>
/// The options and the lifecycle hooks are protected members of <see cref="Executor"/>, which one executor
/// can't call on another, so they are reached through <see cref="UnsafeAccessorAttribute"/> accessors. The
/// hooks are virtual, and the accessors dispatch to the inner executor's overrides.
/// </remarks>
internal static class InnerExecutor
{
    private static readonly MethodInfo AddForwardingRouteMethod =
        typeof(InnerExecutor).GetMethod(nameof(AddForwardingRoute), BindingFlags.NonPublic | BindingFlags.Static)!;

    [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "get_Options")]
    public static extern ExecutorOptions GetOptions(Executor executor);

    [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "InitializeAsync")]
    public static extern ValueTask InitializeAsync(Executor executor, IWorkflowContext context, CancellationToken cancellationToken);

    [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "OnMessageDeliveryStartingAsync")]
    public static extern ValueTask OnMessageDeliveryStartingAsync(Executor executor, IWorkflowContext context, CancellationToken cancellationToken);

    [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "OnMessageDeliveryFinishedAsync")]
    public static extern ValueTask OnMessageDeliveryFinishedAsync(Executor executor, IWorkflowContext context, CancellationToken cancellationToken);

    [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "OnCheckpointingAsync")]
    public static extern ValueTask OnCheckpointingAsync(Executor executor, IWorkflowContext context, CancellationToken cancellationToken);

    [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "OnCheckpointRestoredAsync")]
    public static extern ValueTask OnCheckpointRestoredAsync(Executor executor, IWorkflowContext context, CancellationToken cancellationToken);

    /// <summary>Whether the executor declared that concurrent runs may share it.</summary>
    public static bool IsCrossRunShareable(Executor executor) =>
        new ExecutorInstanceBinding(executor).SupportsConcurrentSharedExecution;

    /// <summary>Disposes the executor the way the workflow runtime does at the end of a run.</summary>
    public static ValueTask DisposeAsync(Executor executor)
    {
        if (executor is IAsyncDisposable asyncDisposable)
            return asyncDisposable.DisposeAsync();

        (executor as IDisposable)?.Dispose();
        return default;
    }

    /// <summary>
    /// Completes a guarded executor's protocol so it matches the inner executor's: the message types the inner
    /// executor sends and yields are declared, and each other type it handles - its catch-all too - gets a route
    /// that hands the message to <paramref name="forward"/>, with the route's type (null for the catch-all).
    /// </summary>
    /// <param name="builder">The guarded executor's protocol, with its own handler already registered.</param>
    /// <param name="inner">The inner executor.</param>
    /// <param name="handledType">The message type the guarded executor handles itself.</param>
    /// <param name="forward">Receives the messages of the inner executor's other types.</param>
    /// <returns>The builder.</returns>
    public static ProtocolBuilder MirrorProtocol(
        ProtocolBuilder builder,
        Executor inner,
        Type handledType,
        Func<object, Type?, IWorkflowContext, CancellationToken, ValueTask> forward)
    {
        var protocol = inner.DescribeProtocol();

        builder.SendsMessageTypes(protocol.Sends)
               .YieldsOutputTypes(protocol.Yields);

        foreach (var type in protocol.Accepts)
        {
            if (type != handledType)
                AddForwardingRouteMethod.MakeGenericMethod(type).Invoke(null, [builder.RouteBuilder, forward]);
        }

        if (protocol.AcceptsAll)
        {
            Func<PortableValue, IWorkflowContext, CancellationToken, ValueTask> catchAll =
                (message, context, cancellationToken) => forward(message, null, context, cancellationToken);
            builder.RouteBuilder.AddCatchAll(catchAll);
        }

        return builder;
    }

    /// <summary>
    /// Runs a message through the inner executor's own routing, as the workflow runtime would. The inner
    /// executor applies its options to the handler's result and raises its own invoked and completed events.
    /// </summary>
    public static async ValueTask ExecuteAsync(Executor executor, object message, IWorkflowContext context, CancellationToken cancellationToken)
    {
        var messageType = message is PortableValue portable ? portable.TypeId : new TypeId(message.GetType());

        try
        {
            await executor.ExecuteCoreAsync(message, messageType, context, cancellationToken).ConfigureAwait(false);
        }
        catch (TargetInvocationException ex) when (ex.InnerException is not null)
        {
            // surface the handler's own exception, as a direct call to the handler would
            ExceptionDispatchInfo.Throw(ex.InnerException);
        }
    }

    private static void AddForwardingRoute<TMessage>(
        RouteBuilder routes,
        Func<object, Type?, IWorkflowContext, CancellationToken, ValueTask> forward)
    {
        Func<TMessage, IWorkflowContext, CancellationToken, ValueTask> handler =
            (message, context, cancellationToken) => forward(message!, typeof(TMessage), context, cancellationToken);
        routes.AddHandler(handler);
    }
}
