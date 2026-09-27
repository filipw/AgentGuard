using Microsoft.Extensions.AI;

namespace AgentGuard.AgentHooks;

/// <summary>
/// The conversation each Agent-Hooks session's run started from - the first model request after its
/// <c>input</c> - kept so the output and tool checks can give the rules the conversation as context,
/// which their own interception points don't carry. Bounded, first in first out.
/// </summary>
internal sealed class RequestHistoryCache(int capacity)
{
    // each entry is stamped, so a queued id only evicts the entry it was queued for, not a later one
    // recorded for the same session
    private readonly Dictionary<string, (IReadOnlyList<ChatMessage> Messages, long Stamp)> _entries = new(StringComparer.Ordinal);
    private readonly Queue<(string SessionId, long Stamp)> _order = new();
    private readonly Lock _lock = new();
    private long _nextStamp;

    /// <summary>Records <paramref name="messages"/> for <paramref name="sessionId"/> unless the session already has an entry.</summary>
    public void TryAdd(string sessionId, IReadOnlyList<ChatMessage> messages)
    {
        lock (_lock)
        {
            if (_entries.ContainsKey(sessionId))
                return;

            var stamp = _nextStamp++;
            _entries[sessionId] = (messages, stamp);
            _order.Enqueue((sessionId, stamp));

            while (_order.Count > capacity)
            {
                var (evicted, evictedStamp) = _order.Dequeue();
                if (_entries.TryGetValue(evicted, out var entry) && entry.Stamp == evictedStamp)
                    _entries.Remove(evicted);
            }
        }
    }

    /// <summary>The messages recorded for <paramref name="sessionId"/>, if any.</summary>
    public IReadOnlyList<ChatMessage>? Get(string sessionId)
    {
        lock (_lock)
        {
            return _entries.TryGetValue(sessionId, out var entry) ? entry.Messages : null;
        }
    }

    /// <summary>Forgets <paramref name="sessionId"/>; its next model request is recorded afresh.</summary>
    public void Remove(string sessionId)
    {
        lock (_lock)
        {
            _entries.Remove(sessionId);
        }
    }
}
