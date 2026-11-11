namespace AgentGuard.Onnx;

/// <summary>
/// Guards a rule's inference session against being released while an evaluation is still using it.
/// Evaluations <see cref="Enter"/> for as long as they use the session; <see cref="Dispose"/> stops new
/// ones from entering and releases the session once the last one in flight has left.
/// </summary>
/// <remarks>
/// The native session behind a rule is freed by its <see cref="IDisposable.Dispose"/>, and running
/// inference on a freed session crashes the process, so the release has to wait for evaluations in
/// flight. Entering and leaving are lock-free, so concurrent evaluations never wait for one another.
/// </remarks>
internal sealed class SessionLifetime : IDisposable
{
    // the top bit of the state marks disposal; the remaining bits count evaluations in flight
    private const int DisposedFlag = int.MinValue;

    private readonly IDisposable? _session;
    private readonly Type _owner;
    private int _state;

    /// <summary>Creates the guard for a rule's session.</summary>
    /// <param name="session">The session to release on disposal, if the rule owns one.</param>
    /// <param name="owner">The rule type, named by the <see cref="ObjectDisposedException"/> thrown after disposal.</param>
    public SessionLifetime(IDisposable? session, Type owner)
    {
        ArgumentNullException.ThrowIfNull(owner);
        _session = session;
        _owner = owner;
    }

    /// <summary>
    /// Marks the start of an evaluation. The session stays alive until the returned usage is disposed.
    /// </summary>
    /// <returns>The usage to dispose when the evaluation no longer touches the session.</returns>
    /// <exception cref="ObjectDisposedException">Thrown when the owner has been disposed.</exception>
    public Usage Enter()
    {
        while (true)
        {
            var state = Volatile.Read(ref _state);
            ObjectDisposedException.ThrowIf((state & DisposedFlag) != 0, _owner);
            if (Interlocked.CompareExchange(ref _state, state + 1, state) == state)
                return new Usage(this);
        }
    }

    /// <summary>
    /// Stops new evaluations from entering and releases the session: immediately when none is in
    /// flight, otherwise as soon as the last one leaves. Calling this again, from any thread, does nothing.
    /// </summary>
    public void Dispose()
    {
        while (true)
        {
            var state = Volatile.Read(ref _state);
            if ((state & DisposedFlag) != 0)
                return;

            if (Interlocked.CompareExchange(ref _state, state | DisposedFlag, state) == state)
            {
                if (state == 0)
                    _session?.Dispose();
                return;
            }
        }
    }

    private void Leave()
    {
        // the evaluation that finds itself last after disposal releases the session on its way out
        if (Interlocked.Decrement(ref _state) == DisposedFlag)
            _session?.Dispose();
    }

    /// <summary>One evaluation's hold on the session. Dispose it exactly once.</summary>
    public readonly struct Usage : IDisposable
    {
        private readonly SessionLifetime? _lifetime;

        internal Usage(SessionLifetime lifetime) => _lifetime = lifetime;

        /// <summary>Marks the end of the evaluation.</summary>
        public void Dispose() => _lifetime?.Leave();
    }
}
