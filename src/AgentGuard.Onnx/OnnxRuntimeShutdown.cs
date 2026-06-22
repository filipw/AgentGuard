using Microsoft.ML.OnnxRuntime;

namespace AgentGuard.Onnx;

/// <summary>
/// Coordinates deterministic teardown of ONNX Runtime native resources at process exit.
/// <para>
/// ONNX Runtime's native env (and its logging manager) is a global whose C++ destructor runs via the
/// C runtime's atexit handlers. On macOS/Linux that destructor can run while the GC finalizer thread is
/// still releasing inference sessions, and the two race on the env's logging mutex - the process then
/// aborts with "mutex lock failed: Invalid argument" (a static-destruction-order race). Releasing the
/// sessions and then the env deterministically during *managed* shutdown - which runs before the native
/// atexit destructors - means the native teardown happens once, in order, with nothing left to race.
/// </para>
/// </summary>
internal static class OnnxRuntimeShutdown
{
    private static readonly object _lock = new();
    private static readonly List<Action> _sessionDisposers = [];
    private static bool _hookRegistered;
    private static bool _shutDown;

    /// <summary>
    /// Installs the single process-exit hook (idempotent) that disposes the shared <see cref="OrtEnv"/>
    /// at managed shutdown. Called whenever a session is created so the env is always torn down cleanly,
    /// even on paths that do not use the pool.
    /// </summary>
    public static void EnsureHookRegistered()
    {
        lock (_lock)
        {
            if (_hookRegistered)
                return;

            _hookRegistered = true;
            AppDomain.CurrentDomain.ProcessExit += (_, _) => ShutDown();
        }
    }

    /// <summary>
    /// Registers a callback that releases a pool's native sessions, run before the env is disposed.
    /// </summary>
    public static void RegisterSessionDisposer(Action disposeSessions)
    {
        lock (_lock)
            _sessionDisposers.Add(disposeSessions);

        EnsureHookRegistered();
    }

    private static void ShutDown()
    {
        lock (_lock)
        {
            if (_shutDown)
                return;
            _shutDown = true;

            foreach (var dispose in _sessionDisposers)
            {
                // best effort: one failing pool must not prevent the env from being disposed.
                try { dispose(); }
                catch { /* shutting down - nothing useful to do with the exception */ }
            }
            _sessionDisposers.Clear();

            // dispose the env last, after every session, so its native destructor runs once while the
            // runtime is still healthy rather than racing the atexit path.
            try { OrtEnv.Instance().Dispose(); }
            catch { /* env may already be gone */ }
        }
    }
}
