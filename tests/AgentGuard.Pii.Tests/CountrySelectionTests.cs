using AgentGuard.Core.Abstractions;
using TasmanianDevil;
using FluentAssertions;
using Xunit;

namespace AgentGuard.Pii.Tests;

public class CountrySelectionTests
{
    private static GuardrailContext Context(string text) => new()
    {
        Text = text,
        Phase = GuardrailPhase.Input,
    };

    [Fact]
    public async Task ShouldRedactCountryEntity_WhenCountriesOptionSet()
    {
        var rule = new PiiRule(new PiiOptions { Countries = ["de"] });
        var result = await rule.EvaluateAsync(Context("Steuer-ID 86095742719"));

        result.IsModified.Should().BeTrue();
        result.ModifiedText.Should().Contain("<DE_TAX_ID>");
    }

    [Fact]
    public async Task ShouldNotRedactCountryEntity_WhenCountriesOptionUnset()
    {
        var rule = new PiiRule();
        var result = await rule.EvaluateAsync(Context("Steuer-ID 86095742719"));

        result.IsModified.Should().BeFalse();
    }
}
