using AgentGuard.Core.Abstractions;
using TasmanianDevil;
using TasmanianDevil.Anonymizer.Operators;
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

    // AG-43: the phase is a guardrail concern, so it moved off the engine's PiiOptions (which
    // drops RedactOutput in its next release) onto AgentGuard's own PiiRuleOptions.
    [Fact]
    public void ShouldBeInputOnly_WhenRedactOutputDisabled()
    {
        var rule = new PiiRule(ruleOptions: new PiiRuleOptions { RedactOutput = false });
        rule.Phase.Should().Be(GuardrailPhase.Input);
    }

    // AG-44: nothing on the guardrail side used to reach this, so two adjacent emails always
    // collapsed into one tag. It is an engine concern, so it is read from PiiOptions.
    [Fact]
    public async Task ShouldAnonymizeAdjacentEntitiesSeparately_WhenMergingDisabled()
    {
        const string text = "write to alice@example.com bob@example.com";

        var merged = await new PiiRule().EvaluateAsync(Context(text));
        var separate = await new PiiRule(new PiiOptions { MergeEntitiesWithSpaces = false })
            .EvaluateAsync(Context(text));

        CountTags(merged.ModifiedText!).Should().Be(1);
        CountTags(separate.ModifiedText!).Should().Be(2);

        static int CountTags(string s) =>
            s.Split("<EMAIL_ADDRESS>", StringSplitOptions.None).Length - 1;
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

    // AG-46: the vocabulary the engine ships changed in 0.3.0 - a Netherlands pack arrived and the
    // two German identity-document entities merged, since they share one format.

    [Fact]
    public async Task ShouldDetectTheNetherlandsPack_WhenOptedIn()
    {
        var rule = new PiiRule(new PiiOptions { Countries = [PiiCountries.Nl] });

        var result = await rule.EvaluateAsync(Context("mijn burgerservicenummer is 111222333"));

        result.IsModified.Should().BeTrue();
        ((IEnumerable<string>)result.Metadata!["entityTypes"]).Should().Contain(PiiEntities.NlBsn);
    }

    [Fact]
    public async Task ShouldNotDetectTheNetherlandsPack_WhenNotOptedIn()
    {
        var rule = new PiiRule();

        var result = await rule.EvaluateAsync(Context("mijn burgerservicenummer is 111222333"));

        result.IsModified.Should().BeFalse("non-US packs are opt-in");
    }

    [Fact]
    public void ShouldTreatTheAlwaysOnUsPackAsAHarmlessNoOp_WhenListedExplicitly()
    {
        var act = () => new PiiRule(new PiiOptions { Countries = [PiiCountries.Us] });

        act.Should().NotThrow();
    }
}
