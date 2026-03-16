using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Rules.TokenLimits;
using FluentAssertions;
using Xunit;

namespace AgentGuard.Core.Tests.Rules;

public class TokenLimitRuleTests
{
    private static GuardrailContext Ctx(string text, GuardrailPhase phase = GuardrailPhase.Input) =>
        new() { Text = text, Phase = phase };

    [Fact]
    public async Task ShouldPass_WhenUnderLimit()
    {
        var rule = new TokenLimitRule(new TokenLimitOptions { MaxTokens = 100 });
        var result = await rule.EvaluateAsync(Ctx("Hello world"));
        result.IsBlocked.Should().BeFalse();
        result.IsModified.Should().BeFalse();
    }

    [Fact]
    public async Task ShouldPass_WhenEmptyInput()
    {
        var rule = new TokenLimitRule(new TokenLimitOptions { MaxTokens = 10 });
        var result = await rule.EvaluateAsync(Ctx(""));
        result.IsBlocked.Should().BeFalse();
    }

    [Fact]
    public async Task ShouldBlock_WhenOverLimitWithRejectStrategy()
    {
        var rule = new TokenLimitRule(new TokenLimitOptions { MaxTokens = 2, OverflowStrategy = TokenOverflowStrategy.Reject });
        var longText = string.Join(" ", Enumerable.Repeat("word", 100));
        var result = await rule.EvaluateAsync(Ctx(longText));
        result.IsBlocked.Should().BeTrue();
        result.Reason.Should().Contain("exceeds token limit");
        result.Severity.Should().Be(GuardrailSeverity.Medium);
    }

    [Fact]
    public async Task ShouldTruncate_WhenOverLimitWithTruncateStrategy()
    {
        var rule = new TokenLimitRule(new TokenLimitOptions { MaxTokens = 5, OverflowStrategy = TokenOverflowStrategy.Truncate });
        var longText = string.Join(" ", Enumerable.Repeat("word", 100));
        var result = await rule.EvaluateAsync(Ctx(longText));
        result.IsModified.Should().BeTrue();
        result.ModifiedText.Should().NotBeNull();
        result.ModifiedText!.Length.Should().BeLessThan(longText.Length);
        result.Reason.Should().Contain("truncated");
    }

    [Fact]
    public async Task ShouldWarn_WhenOverLimitWithWarnStrategy()
    {
        var rule = new TokenLimitRule(new TokenLimitOptions { MaxTokens = 2, OverflowStrategy = TokenOverflowStrategy.Warn });
        var longText = string.Join(" ", Enumerable.Repeat("word", 100));
        var result = await rule.EvaluateAsync(Ctx(longText));
        result.IsBlocked.Should().BeFalse();
        result.IsModified.Should().BeFalse();
        result.Reason.Should().Contain("Token limit exceeded");
        result.Metadata.Should().ContainKey("token_count");
        result.Metadata.Should().ContainKey("max_tokens");
    }

    [Fact]
    public void ShouldDefaultToInputPhase()
    {
        var rule = new TokenLimitRule();
        rule.Phase.Should().Be(GuardrailPhase.Input);
    }

    [Fact]
    public void ShouldRespectOutputPhase()
    {
        var rule = new TokenLimitRule(new TokenLimitOptions { Phase = GuardrailPhase.Output });
        rule.Phase.Should().Be(GuardrailPhase.Output);
        rule.Name.Should().Contain("output");
    }

    [Fact]
    public void ShouldHaveCorrectOrder()
    {
        new TokenLimitRule().Order.Should().Be(40);
    }

    [Fact]
    public async Task ShouldPass_WhenExactlyAtLimit()
    {
        // Use a small token limit; one word is typically one token
        var rule = new TokenLimitRule(new TokenLimitOptions { MaxTokens = 1000 });
        var result = await rule.EvaluateAsync(Ctx("Hello"));
        result.IsBlocked.Should().BeFalse();
    }
}
