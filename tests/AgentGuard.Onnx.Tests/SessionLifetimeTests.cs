using FluentAssertions;
using Xunit;

namespace AgentGuard.Onnx.Tests;

/// <summary>
/// Unit tests for <see cref="SessionLifetime"/>: a rule's session is released exactly once, and never
/// while an evaluation is still using it.
/// </summary>
public class SessionLifetimeTests
{
    [Fact]
    public void ShouldReleaseTheSessionAtOnce_WhenDisposedWithNoEvaluationInFlight()
    {
        var session = new CountingDisposable();
        var lifetime = new SessionLifetime(session, typeof(SessionLifetimeTests));

        lifetime.Enter().Dispose();
        lifetime.Dispose();

        session.DisposeCount.Should().Be(1);
    }

    [Fact]
    public void ShouldKeepTheSessionUntilTheLastEvaluationLeaves_WhenDisposedWhileEvaluationsAreInFlight()
    {
        var session = new CountingDisposable();
        var lifetime = new SessionLifetime(session, typeof(SessionLifetimeTests));
        var first = lifetime.Enter();
        var second = lifetime.Enter();

        lifetime.Dispose();
        session.DisposeCount.Should().Be(0, "two evaluations still use the session");

        first.Dispose();
        session.DisposeCount.Should().Be(0, "one evaluation still uses the session");

        second.Dispose();
        session.DisposeCount.Should().Be(1, "the last evaluation to leave releases the session");
    }

    [Fact]
    public void ShouldReleaseTheSessionOnce_WhenDisposedAgainWhileAnEvaluationIsInFlight()
    {
        var session = new CountingDisposable();
        var lifetime = new SessionLifetime(session, typeof(SessionLifetimeTests));
        var usage = lifetime.Enter();

        lifetime.Dispose();
        lifetime.Dispose();
        usage.Dispose();
        lifetime.Dispose();

        session.DisposeCount.Should().Be(1);
    }

    [Fact]
    public void ShouldThrowObjectDisposedNamingTheOwner_WhenEnteredAfterDispose()
    {
        var lifetime = new SessionLifetime(new CountingDisposable(), typeof(SessionLifetimeTests));
        lifetime.Dispose();

        var act = () => lifetime.Enter();

        act.Should().Throw<ObjectDisposedException>().Which.ObjectName.Should().Be(typeof(SessionLifetimeTests).FullName);
    }

    [Fact]
    public void ShouldRefuseNewEvaluations_WhenDisposedWhileAnEvaluationIsInFlight()
    {
        var lifetime = new SessionLifetime(new CountingDisposable(), typeof(SessionLifetimeTests));
        using var usage = lifetime.Enter();
        lifetime.Dispose();

        var act = () => lifetime.Enter();

        act.Should().Throw<ObjectDisposedException>();
    }

    [Fact]
    public void ShouldWorkWithoutASession_WhenTheRuleOwnsNone()
    {
        var lifetime = new SessionLifetime(session: null, typeof(SessionLifetimeTests));
        var usage = lifetime.Enter();

        lifetime.Dispose();
        usage.Dispose();

        var act = () => lifetime.Enter();
        act.Should().Throw<ObjectDisposedException>();
    }

    [Fact]
    public async Task ShouldNeverReleaseTheSessionUnderAnEvaluation_WhenDisposeRacesConcurrentEvaluations()
    {
        const int Rounds = 200;
        const int Evaluators = 4;

        for (var round = 0; round < Rounds; round++)
        {
            var session = new UseTrackingSession();
            var lifetime = new SessionLifetime(session, typeof(SessionLifetimeTests));
            using var start = new Barrier(Evaluators + 1);

            var evaluators = Enumerable.Range(0, Evaluators)
                .Select(_ => Task.Factory.StartNew(() =>
                {
                    start.SignalAndWait();
                    try
                    {
                        while (true)
                        {
                            using var usage = lifetime.Enter();
                            session.Use();
                        }
                    }
                    catch (ObjectDisposedException)
                    {
                        // the rule was disposed: no further evaluation may start
                    }
                }, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default))
                .ToArray();

            start.SignalAndWait();
            Thread.SpinWait(round * 50);
            lifetime.Dispose();
            await Task.WhenAll(evaluators);

            session.UsedAfterRelease.Should().BeFalse("the session must outlive every evaluation that entered");
            session.ReleaseCount.Should().Be(1);
        }
    }

    /// <summary>A session stand-in that notices being used after, or while, it is released.</summary>
    private sealed class UseTrackingSession : IDisposable
    {
        private int _released;
        private int _usedAfterRelease;

        public bool UsedAfterRelease => Volatile.Read(ref _usedAfterRelease) != 0;

        public int ReleaseCount => Volatile.Read(ref _released);

        public void Use()
        {
            if (Volatile.Read(ref _released) != 0)
                Volatile.Write(ref _usedAfterRelease, 1);

            Thread.SpinWait(20);

            if (Volatile.Read(ref _released) != 0)
                Volatile.Write(ref _usedAfterRelease, 1);
        }

        public void Dispose() => Interlocked.Increment(ref _released);
    }
}
