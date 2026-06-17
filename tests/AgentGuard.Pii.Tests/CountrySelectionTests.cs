using AgentGuard.Core.Abstractions;
using AgentGuard.Pii.Analyzer;
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

    private static AnalyzerEngine Engine(IReadOnlyList<string>? countries) =>
        new(PiiRecognizers.CreateRegistry("en", countries), defaultScoreThreshold: 0.4);

    [Fact]
    public void ShouldDetectCountryEntity_OnlyWhenPackEnabled()
    {
        var on = Engine(["de"]);
        var off = Engine(null);

        on.Analyze("Steuer-ID 86095742719").Should().Contain(r => r.EntityType == "DE_TAX_ID");
        off.Analyze("Steuer-ID 86095742719").Should().NotContain(r => r.EntityType == "DE_TAX_ID");
    }

    [Fact]
    public void ShouldNotLeakCrossCountryEntities_WhenPackDisabled()
    {
        Engine(null).Analyze("nhs 943 476 5919").Should().NotContain(r => r.EntityType == "UK_NHS");
        Engine(["uk"]).Analyze("nhs 943 476 5919").Should().Contain(r => r.EntityType == "UK_NHS");
    }

    [Fact]
    public void ShouldKeepGenericAndUsRecognizers_ByDefault()
    {
        var engine = Engine(null);

        engine.Analyze("email me at a@b.com").Should().Contain(r => r.EntityType == "EMAIL_ADDRESS");
        engine.Analyze("my ssn is 234-56-7890").Should().Contain(r => r.EntityType == "US_SSN");
    }

    [Fact]
    public void ShouldNotDuplicateUsPack_WhenRequestedExplicitly()
    {
        var registry = PiiRecognizers.CreateRegistry("en", ["us", "uk"]);
        registry.Recognizers.Count(r => r.SupportedEntities.Contains("US_SSN")).Should().Be(1);
    }

    [Fact]
    public void ShouldNotDuplicatePack_WhenAliasAndCodeBothRequested()
    {
        // "gb" and "uk" resolve to the same pack and must not be added twice
        var registry = PiiRecognizers.CreateRegistry("en", ["uk", "gb"]);
        registry.Recognizers.Count(r => r.SupportedEntities.Contains("UK_NHS")).Should().Be(1);
    }

    [Fact]
    public void ShouldDetectUkEntities_WhenRequestedByGbAlias()
    {
        Engine(["gb"]).Analyze("nhs 943 476 5919").Should().Contain(r => r.EntityType == "UK_NHS");
    }

    [Fact]
    public void ShouldSurfaceWeakCountryEntity_WhenContextBoostsAboveThreshold()
    {
        var engine = Engine(["uk"]);

        // a bare UK postcode scores 0.1 and is dropped; nearby context lifts it above the threshold
        engine.Analyze("the value is SW1A 1AA").Should().NotContain(r => r.EntityType == "UK_POSTCODE");
        engine.Analyze("delivery postcode SW1A 1AA").Should().Contain(r => r.EntityType == "UK_POSTCODE");
    }

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
