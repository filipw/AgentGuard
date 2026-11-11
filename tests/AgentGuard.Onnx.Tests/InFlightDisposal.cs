using AgentGuard.Core.Abstractions;

namespace AgentGuard.Onnx.Tests;

/// <summary>What happened to a rule's session when the rule was disposed during an evaluation.</summary>
/// <param name="ReleasesDuringEvaluation">Session releases seen after Dispose returned, while the classifier was still running.</param>
/// <param name="ReleasesAfterEvaluation">Session releases seen once the evaluation had finished.</param>
/// <param name="Result">The result of the evaluation that was in flight.</param>
/// <param name="ThrowsObjectDisposedAfterwards">Whether an evaluation started after Dispose throws <see cref="ObjectDisposedException"/>.</param>
internal sealed record InFlightDisposalOutcome(
    int ReleasesDuringEvaluation, int ReleasesAfterEvaluation, GuardrailResult Result, bool ThrowsObjectDisposedAfterwards);

/// <summary>
/// Disposes a rule while one of its evaluations is inside the classifier, the situation of a policy
/// being shut down with requests in flight.
/// </summary>
internal static class InFlightDisposal
{
    /// <summary>
    /// Runs the scenario. <paramref name="createRule"/> gets the session stand-in and a hook the rule's
    /// classifier must call; the hook holds the evaluation inside the classifier until the rule has
    /// been disposed.
    /// </summary>
    public static async Task<InFlightDisposalOutcome> RunAsync<TRule>(Func<CountingDisposable, Action, TRule> createRule)
        where TRule : IGuardrailRule, IDisposable
    {
        var session = new CountingDisposable();
        using var classifying = new ManualResetEventSlim();
        using var resume = new ManualResetEventSlim();
        var rule = createRule(session, () =>
        {
            classifying.Set();
            resume.Wait();
        });
        var context = new GuardrailContext { Text = "hello world", Phase = GuardrailPhase.Input };

        var evaluation = Task.Run(async () => await rule.EvaluateAsync(context));
        classifying.Wait();

        rule.Dispose();
        var releasesDuringEvaluation = session.DisposeCount;
        var throwsAfterwards = false;
        try
        {
            await rule.EvaluateAsync(context);
        }
        catch (ObjectDisposedException)
        {
            throwsAfterwards = true;
        }

        resume.Set();
        var result = await evaluation;

        return new InFlightDisposalOutcome(releasesDuringEvaluation, session.DisposeCount, result, throwsAfterwards);
    }
}
