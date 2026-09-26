using AgentGuard.Azure.Pii;
using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Builders;
using AgentGuard.Core.Configuration;
using AgentGuard.Core.Guardrails;
using FluentAssertions;
using Xunit;

namespace AgentGuard.Azure.Tests;

public class AzurePiiRuleFactoryTests
{
    // nothing listens on the loopback discard port, so the Azure call fails at once and the rule fails
    // open to the local recognizers, which are what these tests observe
    private const string UnreachableEndpoint = "http://127.0.0.1:9";

    private static RuleConfiguration Configuration(string? replacement = null, List<string>? countries = null) => new()
    {
        Type = "AzurePii",
        Endpoint = UnreachableEndpoint,
        SubscriptionKey = "key",
        Entities = ["PERSON"],
        Replacement = replacement,
        Countries = countries,
    };

    private static async Task<GuardrailResult> EvaluateAsync(RuleConfiguration configuration, string text)
    {
        var builder = new GuardrailPolicyBuilder();
        new AzurePiiRuleFactory().Configure(builder, configuration);

        using var policy = (GuardrailPolicy)builder.Build();
        return await policy.Rules.Single().EvaluateAsync(new GuardrailContext { Text = text, Phase = GuardrailPhase.Input });
    }

    [Fact]
    public async Task ShouldRedactWithTheReplacement_WhenOneIsConfigured()
    {
        var result = await EvaluateAsync(Configuration(replacement: "[REDACTED]"), "email john@example.com today");

        result.ModifiedText.Should().Be("email [REDACTED] today");
    }

    [Fact]
    public async Task ShouldDetectCountryEntities_WhenCountriesAreConfigured()
    {
        var result = await EvaluateAsync(Configuration(countries: ["de"]), "Steuer-ID 86095742719");

        result.ModifiedText.Should().Contain("<DE_TAX_ID>");
    }

    [Fact]
    public async Task ShouldKeepThePiiDefaults_WhenReplacementAndCountriesAreNotConfigured()
    {
        var result = await EvaluateAsync(Configuration(), "email john@example.com, Steuer-ID 86095742719");

        result.ModifiedText.Should().Contain("<EMAIL_ADDRESS>").And.Contain("86095742719");
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-5)]
    public void ShouldRejectTheTimeout_WhenBelowOneSecond(int timeoutSeconds)
    {
        var configuration = Configuration();
        configuration.TimeoutSeconds = timeoutSeconds;

        var act = () => new AzurePiiRuleFactory().Configure(new GuardrailPolicyBuilder(), configuration);

        act.Should().Throw<InvalidOperationException>().WithMessage("AzurePii: TimeoutSeconds must be at least 1*");
    }

    [Theory]
    [InlineData("Phi")]
    [InlineData("phi")]
    [InlineData("None")]
    public void ShouldAcceptTheDomain_WhenItIsAMemberName(string domain)
    {
        var configuration = Configuration();
        configuration.Domain = domain;
        var builder = new GuardrailPolicyBuilder();

        new AzurePiiRuleFactory().Configure(builder, configuration);

        using var policy = (GuardrailPolicy)builder.Build();
        policy.Rules.Should().ContainSingle().Which.Name.Should().Be("pii");
    }

    [Fact]
    public void ShouldRejectTheDomain_WhenItIsANumber()
    {
        var configuration = Configuration();
        configuration.Domain = "7";

        var act = () => new AzurePiiRuleFactory().Configure(new GuardrailPolicyBuilder(), configuration);

        act.Should().Throw<InvalidOperationException>().WithMessage("'7' is not a valid Domain*");
    }
}
