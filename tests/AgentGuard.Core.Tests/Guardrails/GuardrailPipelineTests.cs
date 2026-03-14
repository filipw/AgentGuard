using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Guardrails;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;

namespace AgentGuard.Core.Tests.Guardrails;

public class GuardrailPipelineTests
{
    private static GuardrailContext Ctx(string text, GuardrailPhase phase = GuardrailPhase.Input) => new() { Text = text, Phase = phase };

    [Fact]
    public async Task ShouldPass_WhenNoRules()
    {
        var p = new GuardrailPipeline(new GuardrailPolicy("t", []), NullLogger<GuardrailPipeline>.Instance);
        var r = await p.RunAsync(Ctx("hello"));
        r.IsBlocked.Should().BeFalse();
        r.FinalText.Should().Be("hello");
    }

    [Fact]
    public async Task ShouldBlock_WhenRuleBlocks()
    {
        var rule = new TestRule("b", GuardrailPhase.Input, _ => ValueTask.FromResult(GuardrailResult.Blocked("no")));
        var p = new GuardrailPipeline(new GuardrailPolicy("t", [rule]), NullLogger<GuardrailPipeline>.Instance);
        var r = await p.RunAsync(Ctx("hello"));
        r.IsBlocked.Should().BeTrue();
        r.BlockingResult!.Reason.Should().Be("no");
    }

    [Fact]
    public async Task ShouldModifyText_WhenRuleModifies()
    {
        var rule = new TestRule("m", GuardrailPhase.Input, _ => ValueTask.FromResult(GuardrailResult.Modified("goodbye", "replaced")));
        var p = new GuardrailPipeline(new GuardrailPolicy("t", [rule]), NullLogger<GuardrailPipeline>.Instance);
        var r = await p.RunAsync(Ctx("hello"));
        r.IsBlocked.Should().BeFalse();
        r.WasModified.Should().BeTrue();
        r.FinalText.Should().Be("goodbye");
    }

    [Fact]
    public async Task ShouldChainModifications()
    {
        var r1 = new TestRule("r1", GuardrailPhase.Input, 1, c => ValueTask.FromResult(GuardrailResult.Modified(c.Text.Replace("hello", "hi"), "s1")));
        var r2 = new TestRule("r2", GuardrailPhase.Input, 2, c => ValueTask.FromResult(GuardrailResult.Modified(c.Text + " world", "s2")));
        var p = new GuardrailPipeline(new GuardrailPolicy("t", [r2, r1]), NullLogger<GuardrailPipeline>.Instance);
        var r = await p.RunAsync(Ctx("hello"));
        r.FinalText.Should().Be("hi world");
    }

    [Fact]
    public async Task ShouldStopAtFirstBlock()
    {
        var called = false;
        var r1 = new TestRule("b", GuardrailPhase.Input, 1, _ => ValueTask.FromResult(GuardrailResult.Blocked("stop")));
        var r2 = new TestRule("a", GuardrailPhase.Input, 2, _ => { called = true; return ValueTask.FromResult(GuardrailResult.Passed()); });
        var p = new GuardrailPipeline(new GuardrailPolicy("t", [r1, r2]), NullLogger<GuardrailPipeline>.Instance);
        await p.RunAsync(Ctx("hello"));
        called.Should().BeFalse();
    }

    [Fact]
    public async Task ShouldOnlyRunRulesMatchingPhase()
    {
        var inCalled = false; var outCalled = false;
        var ri = new TestRule("i", GuardrailPhase.Input, c => { inCalled = true; return ValueTask.FromResult(GuardrailResult.Passed()); });
        var ro = new TestRule("o", GuardrailPhase.Output, c => { outCalled = true; return ValueTask.FromResult(GuardrailResult.Passed()); });
        var p = new GuardrailPipeline(new GuardrailPolicy("t", [ri, ro]), NullLogger<GuardrailPipeline>.Instance);
        await p.RunAsync(Ctx("hello", GuardrailPhase.Input));
        inCalled.Should().BeTrue();
        outCalled.Should().BeFalse();
    }

    [Fact]
    public async Task ShouldCollectAllResults()
    {
        var r1 = new TestRule("r1", GuardrailPhase.Input, _ => ValueTask.FromResult(GuardrailResult.Passed()));
        var r2 = new TestRule("r2", GuardrailPhase.Input, _ => ValueTask.FromResult(GuardrailResult.Passed()));
        var p = new GuardrailPipeline(new GuardrailPolicy("t", [r1, r2]), NullLogger<GuardrailPipeline>.Instance);
        var r = await p.RunAsync(Ctx("hello"));
        r.AllResults.Should().HaveCount(2);
    }

    private class TestRule(string name, GuardrailPhase phase, Func<GuardrailContext, ValueTask<GuardrailResult>> eval) : IGuardrailRule
    {
        public TestRule(string name, GuardrailPhase phase, int order, Func<GuardrailContext, ValueTask<GuardrailResult>> eval) : this(name, phase, eval) => Order = order;
        public string Name => name;
        public GuardrailPhase Phase => phase;
        public int Order { get; } = 100;
        public ValueTask<GuardrailResult> EvaluateAsync(GuardrailContext context, CancellationToken ct = default) => eval(context);
    }
}
