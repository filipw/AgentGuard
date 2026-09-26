namespace AgentGuard.Onnx.Tests;

/// <summary>Stands in for a rule's inference session and counts how often it is released.</summary>
internal sealed class CountingDisposable : IDisposable
{
    private int _disposeCount;

    public int DisposeCount => Volatile.Read(ref _disposeCount);

    public void Dispose() => Interlocked.Increment(ref _disposeCount);

    /// <summary>
    /// Disposes a fresh rule from several threads at once, round after round, and returns how often
    /// each round's session was released.
    /// </summary>
    public static IReadOnlyList<int> DisposeConcurrently(Func<CountingDisposable, IDisposable> createRule, int rounds = 50, int threads = 4)
    {
        var counts = new List<int>(rounds);
        for (var round = 0; round < rounds; round++)
        {
            var session = new CountingDisposable();
            var rule = createRule(session);
            using var start = new Barrier(threads);
            var workers = Enumerable.Range(0, threads)
                .Select(_ => Task.Factory.StartNew(() =>
                {
                    start.SignalAndWait();
                    rule.Dispose();
                }, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default))
                .ToArray();
            Task.WaitAll(workers);
            counts.Add(session.DisposeCount);
        }

        return counts;
    }
}
