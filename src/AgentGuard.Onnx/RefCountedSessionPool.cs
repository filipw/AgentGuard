namespace AgentGuard.Onnx;

/// <summary>
/// A pooled inference session whose native resources are released by the pool when the last
/// reference is dropped. The public <see cref="IDisposable.Dispose"/> releases the caller's
/// reference; <see cref="ReleaseResources"/> is invoked by the pool to free the underlying session.
/// </summary>
internal interface IRefCountedSession : IDisposable
{
    /// <summary>Frees the underlying native session. Called by the pool when the reference count reaches zero.</summary>
    void ReleaseResources();
}

/// <summary>
/// Process-wide, reference-counted cache of expensive <see cref="IRefCountedSession"/> instances
/// (ONNX inference sessions) keyed by their construction inputs. Multiple rules/recognizers pointing
/// at the same model files share one session; the underlying session is freed once every holder has
/// disposed. Each session type owns one static instance of this pool.
/// </summary>
/// <typeparam name="TKey">The cache key (typically a record of the model/tokenizer paths and caps).</typeparam>
/// <typeparam name="TSession">The pooled session type.</typeparam>
internal sealed class RefCountedSessionPool<TKey, TSession>
    where TKey : notnull
    where TSession : class, IRefCountedSession
{
    private sealed class CacheEntry
    {
        public required TSession Session { get; init; }
        public int RefCount { get; set; }
    }

    private readonly Dictionary<TKey, CacheEntry> _cache = [];
    private readonly object _lock = new();

    /// <summary>
    /// Returns the shared session for <paramref name="key"/>, building it with
    /// <paramref name="factory"/> on first use. Reference-counted: balance each call with a
    /// <see cref="Release"/> (via <see cref="IDisposable.Dispose"/>).
    /// </summary>
    public TSession Acquire(TKey key, Func<TSession> factory)
    {
        lock (_lock)
        {
            if (_cache.TryGetValue(key, out var entry))
            {
                entry.RefCount++;
                return entry.Session;
            }

            var session = factory();
            _cache[key] = new CacheEntry { Session = session, RefCount = 1 };
            return session;
        }
    }

    /// <summary>Releases one reference for <paramref name="key"/>; frees the session at zero.</summary>
    public void Release(TKey key)
    {
        lock (_lock)
        {
            if (!_cache.TryGetValue(key, out var entry))
                return; // already fully released

            entry.RefCount--;
            if (entry.RefCount <= 0)
            {
                _cache.Remove(key);
                entry.Session.ReleaseResources();
            }
        }
    }

    /// <summary>Number of distinct loaded sessions currently cached. For tests/diagnostics.</summary>
    public int ActiveCount
    {
        get { lock (_lock) { return _cache.Count; } }
    }
}
