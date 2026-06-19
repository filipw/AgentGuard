using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Builders;
using AgentGuard.Core.Rules;
using AgentGuard.Pii;
using FluentAssertions;
using Xunit;

namespace AgentGuard.Core.Tests.Rules;

public class ConditionalGuardrailRuleTests
{
    private static GuardrailContext Ctx(string text = "x", GuardrailPhase phase = GuardrailPhase.Input) =>
        new() { Text = text, Phase = phase };

    private sealed class BlockingRule : IGuardrailRule
    {
        public string Name => "blocking";
        public GuardrailPhase Phase => GuardrailPhase.Input;
        public int Order => 11;
        public bool WasEvaluated { get; private set; }

        public ValueTask<GuardrailResult> EvaluateAsync(GuardrailContext context, CancellationToken ct = default)
        {
            WasEvaluated = true;
            return ValueTask.FromResult(GuardrailResult.Blocked("blocked by inner"));
        }
    }

    [Fact]
    public async Task ShouldEvaluateInner_WhenPredicateTrue()
    {
        var inner = new BlockingRule();
        var rule = new ConditionalGuardrailRule(inner, _ => true);

        var result = await rule.EvaluateAsync(Ctx());

        result.IsBlocked.Should().BeTrue();
        inner.WasEvaluated.Should().BeTrue();
    }

    [Fact]
    public async Task ShouldSkipInner_WhenPredicateFalse()
    {
        var inner = new BlockingRule();
        var rule = new ConditionalGuardrailRule(inner, _ => false);

        var result = await rule.EvaluateAsync(Ctx());

        result.IsBlocked.Should().BeFalse("a skipped rule passes through");
        inner.WasEvaluated.Should().BeFalse("the inner rule must not run when gated off");
    }

    [Fact]
    public async Task ShouldSupportAsyncPredicate()
    {
        var inner = new BlockingRule();
        var rule = new ConditionalGuardrailRule(inner, (_, _) => ValueTask.FromResult(false));

        var result = await rule.EvaluateAsync(Ctx());

        result.IsBlocked.Should().BeFalse();
        inner.WasEvaluated.Should().BeFalse();
    }

    [Fact]
    public async Task ShouldPassContextToPredicate()
    {
        var inner = new BlockingRule();
        // gate off when language is non-English
        var rule = new ConditionalGuardrailRule(inner,
            ctx => ctx.Properties.TryGetValue("language", out var l) && (string)l == "en");

        var english = await rule.EvaluateAsync(new GuardrailContext
        {
            Text = "x",
            Phase = GuardrailPhase.Input,
            Properties = { ["language"] = "en" }
        });
        var german = await rule.EvaluateAsync(new GuardrailContext
        {
            Text = "x",
            Phase = GuardrailPhase.Input,
            Properties = { ["language"] = "de" }
        });

        english.IsBlocked.Should().BeTrue("rule active for English");
        german.IsBlocked.Should().BeFalse("rule gated off for German");
    }

    [Fact]
    public void ShouldDelegateMetadataToInner()
    {
        var inner = new BlockingRule();
        var rule = new ConditionalGuardrailRule(inner, _ => true);

        rule.Name.Should().Be("blocking");
        rule.Phase.Should().Be(GuardrailPhase.Input);
        rule.Order.Should().Be(11);
        rule.InnerRule.Should().BeSameAs(inner);
    }

    [Fact]
    public void ShouldThrow_WhenInnerNull()
    {
        var act = () => new ConditionalGuardrailRule(null!, _ => true);
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void ShouldThrow_WhenPredicateNull()
    {
        var act = () => new ConditionalGuardrailRule(new BlockingRule(), (Func<GuardrailContext, bool>)null!);
        act.Should().Throw<ArgumentNullException>();
    }

    // --- Builder integration: .When / .Unless ---

    [Fact]
    public void When_ShouldWrapLastRule()
    {
        var policy = new GuardrailPolicyBuilder()
            .BlockPromptInjection()
            .When(_ => true)
            .Build();

        var rule = policy.Rules.Should().ContainSingle().Subject;
        rule.Should().BeOfType<ConditionalGuardrailRule>();
        // name/order preserved so ordering and telemetry are unchanged
        rule.Name.Should().Be("prompt-injection");
    }

    [Fact]
    public void When_ShouldGateOnlyTheLastRule()
    {
        // two rules; only the second (gated) one is conditional
        var policy = new GuardrailPolicyBuilder()
            .AddRule(new BlockingRule())            // order 11, always runs
            .RedactPii()
            .When(_ => false)                        // gate the PII rule off
            .Build();

        policy.Rules.Should().HaveCount(2);
        policy.Rules.OfType<ConditionalGuardrailRule>().Should().ContainSingle()
            .Which.Name.Should().Be("pii");
    }

    [Fact]
    public async Task Unless_ShouldSkipRule_WhenPredicateTrue()
    {
        var policy = new GuardrailPolicyBuilder()
            .AddRule(new BlockingRule())
            .Unless(ctx => ctx.Properties.ContainsKey("skip"))
            .Build();

        var rule = policy.Rules.Single();

        var skipped = await rule.EvaluateAsync(new GuardrailContext
        {
            Text = "x",
            Phase = GuardrailPhase.Input,
            Properties = { ["skip"] = true }
        });
        var active = await rule.EvaluateAsync(Ctx());

        skipped.IsBlocked.Should().BeFalse();
        active.IsBlocked.Should().BeTrue();
    }

    [Fact]
    public void When_ShouldThrow_WhenNoRuleAdded()
    {
        var act = () => new GuardrailPolicyBuilder().When(_ => true);
        act.Should().Throw<InvalidOperationException>();
    }
}
