using AgentGuard.Core.Builders;
using AgentGuard.Core.Rules.PII;
using AgentGuard.Core.Streaming;
using FluentAssertions;
using Xunit;

namespace AgentGuard.Core.Tests.Builders;

public class GuardrailPolicyBuilderTests
{
    [Fact]
    public void ShouldBuildEmptyPolicy()
    {
        var p = new GuardrailPolicyBuilder("empty").Build();
        p.Name.Should().Be("empty");
        p.Rules.Should().BeEmpty();
    }

    [Fact]
    public void ShouldAddPromptInjectionRule()
    {
        new GuardrailPolicyBuilder().BlockPromptInjection().Build()
            .Rules.Should().ContainSingle().Which.Name.Should().Be("prompt-injection");
    }

    [Fact]
    public void ShouldAddPiiRedactionRule()
    {
        new GuardrailPolicyBuilder().RedactPII(PiiCategory.Email | PiiCategory.Phone).Build()
            .Rules.Should().ContainSingle().Which.Name.Should().Be("pii-redaction");
    }

    [Fact]
    public void ShouldChainMultipleRules()
    {
        new GuardrailPolicyBuilder().BlockPromptInjection().RedactPII().LimitInputTokens(2000).Build()
            .Rules.Should().HaveCount(3);
    }

    [Fact]
    public void ShouldOrderRulesByPriority()
    {
        var p = new GuardrailPolicyBuilder()
            .LimitInputTokens(2000).RedactPII().BlockPromptInjection().Build();
        p.Rules[0].Name.Should().Be("prompt-injection");
        p.Rules[1].Name.Should().Be("pii-redaction");
        p.Rules[2].Name.Should().Contain("token-limit");
    }

    [Fact]
    public void ShouldConfigureViolationHandler()
    {
        new GuardrailPolicyBuilder().BlockPromptInjection().OnViolation(v => v.RejectWithMessage("Nope.")).Build()
            .ViolationHandler.Should().NotBeNull();
    }

    [Fact]
    public void ShouldAddCustomRule()
    {
        new GuardrailPolicyBuilder()
            .AddRule("custom", Abstractions.GuardrailPhase.Output, (ctx, ct) => ValueTask.FromResult(Abstractions.GuardrailResult.Passed()))
            .Build().Rules.Should().ContainSingle().Which.Name.Should().Be("custom");
    }

    [Fact]
    public void ShouldConfigureProgressiveStreaming()
    {
        var policy = new GuardrailPolicyBuilder()
            .BlockPromptInjection()
            .UseProgressiveStreaming()
            .Build();

        policy.ProgressiveStreaming.Should().NotBeNull();
    }

    [Fact]
    public void ShouldConfigureProgressiveStreamingWithOptions()
    {
        var policy = new GuardrailPolicyBuilder()
            .BlockPromptInjection()
            .UseProgressiveStreaming(new ProgressiveStreamingOptions
            {
                EvaluationIntervalChars = 100
            })
            .Build();

        policy.ProgressiveStreaming.Should().NotBeNull();
    }

    [Fact]
    public void ShouldDefaultToNoProgressiveStreaming()
    {
        var policy = new GuardrailPolicyBuilder()
            .BlockPromptInjection()
            .Build();

        policy.ProgressiveStreaming.Should().BeNull();
    }
}
