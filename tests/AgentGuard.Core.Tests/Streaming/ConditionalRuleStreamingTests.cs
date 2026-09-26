using System.Runtime.CompilerServices;
using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Builders;
using AgentGuard.Core.Rules;
using AgentGuard.Core.Streaming;
using FluentAssertions;
using Xunit;

namespace AgentGuard.Core.Tests.Streaming;

// a .When()/.Unless() gate keeps the gated rule's streaming mode
public class ConditionalRuleStreamingTests
{
    [Fact]
    public async Task ShouldEvaluateGatedFinalOnlyRuleOnce_WhenStreamingProgressively()
    {
        var rule = new CountingRule(StreamingEvaluationMode.FinalOnly);
        var policy = new GuardrailPolicyBuilder()
            .AddRule(rule).When(_ => true)
            .UseProgressiveStreaming(new ProgressiveStreamingOptions { EvaluationIntervalChars = 10, MinCharsBeforeFirstCheck = 10 })
            .Build();

        await Drain(new StreamingGuardrailPipeline(policy, policy.ProgressiveStreaming));

        rule.Evaluations.Should().Be(1, "a final-only rule runs once, in the end-of-stream check");
    }

    [Fact]
    public async Task ShouldEvaluateGatedEveryCheckRuleProgressively_WhenStreamingProgressively()
    {
        var rule = new CountingRule(StreamingEvaluationMode.EveryCheck);
        var policy = new GuardrailPolicyBuilder()
            .AddRule(rule).When(_ => true)
            .UseProgressiveStreaming(new ProgressiveStreamingOptions { EvaluationIntervalChars = 10, MinCharsBeforeFirstCheck = 10 })
            .Build();

        await Drain(new StreamingGuardrailPipeline(policy, policy.ProgressiveStreaming));

        rule.Evaluations.Should().BeGreaterThan(1);
    }

    [Fact]
    public void Unwrap_ShouldReturnInnermostRule_WhenGatesAreNested()
    {
        var rule = new CountingRule(StreamingEvaluationMode.FinalOnly);
        var gated = new ConditionalGuardrailRule(new ConditionalGuardrailRule(rule, _ => true), _ => false);

        gated.Unwrap().Should().BeSameAs(rule);
        rule.Unwrap().Should().BeSameAs(rule);
    }

    private static async Task Drain(StreamingGuardrailPipeline pipeline)
    {
        var context = new GuardrailContext { Text = "", Phase = GuardrailPhase.Output };
        await foreach (var _ in pipeline.ProcessStreamAsync(Chunks(), context))
        {
        }
    }

    private static async IAsyncEnumerable<string> Chunks([EnumeratorCancellation] CancellationToken ct = default)
    {
        for (var i = 0; i < 10; i++)
        {
            ct.ThrowIfCancellationRequested();
            yield return new string('a', 20);
            await Task.Yield();
        }
    }

    private sealed class CountingRule(StreamingEvaluationMode mode) : IGuardrailRule, IStreamingGuardrailRule
    {
        public int Evaluations { get; private set; }

        public string Name => "counting";

        public GuardrailPhase Phase => GuardrailPhase.Output;

        public StreamingEvaluationMode StreamingMode => mode;

        public ValueTask<GuardrailResult> EvaluateAsync(GuardrailContext context, CancellationToken cancellationToken = default)
        {
            Evaluations++;
            return ValueTask.FromResult(GuardrailResult.Passed());
        }
    }
}
