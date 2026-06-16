using AgentGuard.Core.Abstractions;
using AgentGuard.Pii.Anonymizer.Operators;
using FluentAssertions;
using Xunit;

namespace AgentGuard.Pii.Tests;

public class PiiRuleTests
{
    private static GuardrailContext Context(string text) => new()
    {
        Text = text,
        Phase = GuardrailPhase.Input,
    };

    [Fact]
    public void ShouldHaveExpectedMetadata()
    {
        var rule = new PiiRule();
        rule.Name.Should().Be("pii");
        rule.Order.Should().Be(20);
        rule.Phase.Should().Be(GuardrailPhase.Both);
    }

    [Fact]
    public void ShouldBeInputOnly_WhenRedactOutputDisabled()
    {
        var rule = new PiiRule(new PiiOptions { RedactOutput = false });
        rule.Phase.Should().Be(GuardrailPhase.Input);
    }

    [Fact]
    public async Task ShouldPass_WhenNoPii()
    {
        var rule = new PiiRule();
        var result = await rule.EvaluateAsync(Context("the weather is nice today"));

        result.IsModified.Should().BeFalse();
        result.IsBlocked.Should().BeFalse();
    }

    [Fact]
    public async Task ShouldModifyAndReport_WhenPiiDetected()
    {
        var rule = new PiiRule();
        var result = await rule.EvaluateAsync(Context("email john@example.com and card 4012888888881881"));

        result.IsModified.Should().BeTrue();
        result.ModifiedText.Should().Contain("<EMAIL_ADDRESS>");
        result.ModifiedText.Should().Contain("<CREDIT_CARD>");
        result.Reason.Should().Contain("CREDIT_CARD");
        result.Metadata.Should().ContainKey("entityTypes");
    }

    [Fact]
    public async Task ShouldUseFlatReplacement_WhenConfigured()
    {
        var rule = new PiiRule(new PiiOptions { Replacement = "[REDACTED]" });
        var result = await rule.EvaluateAsync(Context("my email is john@example.com"));

        result.ModifiedText.Should().Be("my email is [REDACTED]");
    }

    [Fact]
    public async Task ShouldRestrictToRequestedEntities()
    {
        var rule = new PiiRule(new PiiOptions { Entities = ["EMAIL_ADDRESS"] });
        var result = await rule.EvaluateAsync(Context("email john@example.com card 4012888888881881"));

        result.ModifiedText.Should().Contain("<EMAIL_ADDRESS>");
        result.ModifiedText.Should().Contain("4012888888881881"); // credit card not requested
    }

    [Fact]
    public async Task ShouldRespectAllowList()
    {
        var rule = new PiiRule(new PiiOptions { Entities = ["EMAIL_ADDRESS"], AllowList = ["john@example.com"] });
        var result = await rule.EvaluateAsync(Context("my email is john@example.com"));

        result.IsModified.Should().BeFalse();
    }

    [Fact]
    public async Task ShouldApplyPerEntityOperators()
    {
        var options = new PiiOptions
        {
            Operators = new Dictionary<string, OperatorConfig>
            {
                ["CREDIT_CARD"] = new("mask", new Dictionary<string, object>
                {
                    [OperatorParams.MaskingChar] = "*",
                    [OperatorParams.CharsToMask] = 12,
                    [OperatorParams.FromEnd] = false,
                }),
                ["DEFAULT"] = new("replace"),
            },
        };
        var rule = new PiiRule(options);
        var result = await rule.EvaluateAsync(Context("card 4012888888881881 here"));

        result.ModifiedText.Should().Be("card ************1881 here");
    }
}
