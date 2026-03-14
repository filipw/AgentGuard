using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Rules.PII;
using FluentAssertions;

namespace AgentGuard.Core.Tests.Rules;

public class PiiRedactionRuleTests
{
    private readonly PiiRedactionRule _rule = new();
    private GuardrailContext Ctx(string text) => new() { Text = text, Phase = GuardrailPhase.Input };

    [Fact]
    public async Task ShouldRedact_EmailAddress()
    {
        var r = await _rule.EvaluateAsync(Ctx("Contact me at john.doe@example.com for details"));
        r.IsModified.Should().BeTrue();
        r.ModifiedText.Should().Contain("[REDACTED]").And.NotContain("john.doe@example.com");
    }

    [Fact]
    public async Task ShouldRedact_PhoneNumber()
    {
        var r = await _rule.EvaluateAsync(Ctx("Call me at (555) 123-4567"));
        r.IsModified.Should().BeTrue();
        r.ModifiedText.Should().NotContain("555");
    }

    [Fact]
    public async Task ShouldRedact_SSN()
    {
        var r = await _rule.EvaluateAsync(Ctx("My SSN is 123-45-6789"));
        r.IsModified.Should().BeTrue();
        r.ModifiedText.Should().NotContain("123-45-6789");
    }

    [Fact]
    public async Task ShouldRedact_CreditCard()
    {
        var r = await _rule.EvaluateAsync(Ctx("Card number: 4111-1111-1111-1111"));
        r.IsModified.Should().BeTrue();
        r.ModifiedText.Should().NotContain("4111");
    }

    [Fact]
    public async Task ShouldRedact_MultiplePiiTypes()
    {
        var r = await _rule.EvaluateAsync(Ctx("Email: test@test.com, phone: 555-123-4567, SSN: 123-45-6789"));
        r.IsModified.Should().BeTrue();
        r.Reason.Should().Contain("email").And.Contain("phone").And.Contain("ssn");
    }

    [Fact]
    public async Task ShouldPass_NoPii()
    {
        var r = await _rule.EvaluateAsync(Ctx("What is the weather like today?"));
        r.IsBlocked.Should().BeFalse();
        r.IsModified.Should().BeFalse();
    }

    [Fact]
    public async Task ShouldUseCustomReplacement()
    {
        var rule = new PiiRedactionRule(new() { Replacement = "***" });
        var r = await rule.EvaluateAsync(Ctx("Email me at user@domain.com"));
        r.ModifiedText.Should().Contain("***");
    }

    [Fact]
    public async Task ShouldRespectCategoryFilter()
    {
        var rule = new PiiRedactionRule(new() { Categories = PiiCategory.Email });
        var r = await rule.EvaluateAsync(Ctx("Email: test@test.com, SSN: 123-45-6789"));
        r.IsModified.Should().BeTrue();
        r.ModifiedText.Should().NotContain("test@test.com").And.Contain("123-45-6789");
    }

    [Fact]
    public async Task ShouldRedact_CustomPattern()
    {
        var rule = new PiiRedactionRule(new() { CustomPatterns = new Dictionary<string, string> { ["emp-id"] = @"EMP-\d{6}" } });
        var r = await rule.EvaluateAsync(Ctx("Employee ID: EMP-123456"));
        r.IsModified.Should().BeTrue();
        r.ModifiedText.Should().NotContain("EMP-123456");
    }
}
