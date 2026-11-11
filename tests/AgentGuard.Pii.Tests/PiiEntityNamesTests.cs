using AgentGuard.Core.Abstractions;
using FluentAssertions;
using TasmanianDevil;
using Xunit;

namespace AgentGuard.Pii.Tests;

/// <summary>
/// How configured PII entity type names are checked, by <see cref="PiiEntityNames"/> and by
/// <see cref="PiiRule"/> for its own entity filter.
/// </summary>
public class PiiEntityNamesTests
{
    private static GuardrailContext Context(string text) => new()
    {
        Text = text,
        Phase = GuardrailPhase.Input,
    };

    [Fact]
    public void Canonical_ShouldHoldTheEngineEntityTypes()
    {
        PiiEntityNames.Canonical.Should().Contain([PiiEntities.Person, PiiEntities.EmailAddress, PiiEntities.UsSsn])
            .And.OnlyHaveUniqueItems();
    }

    [Theory]
    [InlineData("EMAIL_ADDRESS")]
    [InlineData("email_address")]
    [InlineData("Email_Address")]
    [InlineData("  EMAIL_ADDRESS ")]
    public void Resolve_ShouldReturnTheAcceptedSpelling_WhateverTheCaseOrPadding(string name)
    {
        var resolved = PiiEntityNames.Resolve([name], ["EMAIL_ADDRESS", "PERSON"]);

        resolved.Should().Equal("EMAIL_ADDRESS");
    }

    [Fact]
    public void Resolve_ShouldReturnTheTarget_WhenTheNameIsAnAlias()
    {
        var aliases = new Dictionary<string, string> { ["Person"] = "PERSON", ["Email"] = "EMAIL_ADDRESS" };

        var resolved = PiiEntityNames.Resolve(["email", "Person"], ["PERSON", "EMAIL_ADDRESS"], aliases);

        resolved.Should().Equal("EMAIL_ADDRESS", "PERSON");
    }

    [Fact]
    public void Resolve_ShouldPreferTheAcceptedName_WhenItIsAlsoAnAlias()
    {
        var aliases = new Dictionary<string, string> { ["URL"] = "LINK" };

        var resolved = PiiEntityNames.Resolve(["url"], ["URL"], aliases);

        resolved.Should().Equal("URL");
    }

    [Fact]
    public void Resolve_ShouldReturnEachEntityOnce_WhenItIsNamedTwice()
    {
        var aliases = new Dictionary<string, string> { ["Person"] = "PERSON" };

        var resolved = PiiEntityNames.Resolve(["PERSON", "person", "Person"], ["PERSON"], aliases);

        resolved.Should().Equal("PERSON");
    }

    [Theory]
    [InlineData("EMAIL_ADRESS")]
    [InlineData("")]
    [InlineData("   ")]
    public void Resolve_ShouldThrowListingWhatIsAccepted_WhenANameIsUnknown(string name)
    {
        var aliases = new Dictionary<string, string> { ["Person"] = "PERSON" };

        var act = () => PiiEntityNames.Resolve(["PERSON", name], ["PERSON", "EMAIL_ADDRESS"], aliases, "options");

        act.Should().Throw<ArgumentException>()
            .WithParameterName("options")
            .WithMessage($"'{name}' is not a PII entity type the detector finds. Accepted: EMAIL_ADDRESS, PERSON. Also accepted: Person (for PERSON).*");
    }

    // PiiRule's own filter: a name no recognizer answers to would switch that detection off

    [Theory]
    [InlineData("EMAIL_ADRESS")]
    [InlineData("EMAIL")]
    public void PiiRule_ShouldThrow_WhenAnEntityIsNotDetectedByAnyRecognizer(string entity)
    {
        var act = () => new PiiRule(new PiiOptions { Entities = [PiiEntities.UsSsn, entity] });

        act.Should().Throw<ArgumentException>().WithMessage($"'{entity}' is not a PII entity type the detector finds. Accepted:*EMAIL_ADDRESS*");
    }

    [Fact]
    public void PiiRule_ShouldThrow_WhenAnEntityBelongsToACountryPackThatIsNotEnabled()
    {
        var act = () => new PiiRule(new PiiOptions { Entities = [PiiEntities.UkNhs] });

        act.Should().Throw<ArgumentException>().WithMessage($"'{PiiEntities.UkNhs}'*");
    }

    [Fact]
    public void PiiRule_ShouldAcceptACountryEntity_WhenItsCountryPackIsEnabled()
    {
        var act = () => new PiiRule(new PiiOptions { Entities = [PiiEntities.UkNhs], Countries = ["uk"] });

        act.Should().NotThrow();
    }

    [Theory]
    [InlineData("EMAIL_ADDRESS")]
    [InlineData("email_address")]
    [InlineData(" Email_Address ")]
    public async Task PiiRule_ShouldRedactOnlyTheNamedEntity_WhateverTheCaseOfItsName(string entity)
    {
        var rule = new PiiRule(new PiiOptions { Entities = [entity] });

        var result = await rule.EvaluateAsync(Context("john@example.com, SSN 536-90-4399"));

        result.ModifiedText.Should().Be("<EMAIL_ADDRESS>, SSN 536-90-4399");
    }

    [Fact]
    public async Task PiiRule_ShouldDetectEverything_WhenTheEntityListIsEmpty()
    {
        var rule = new PiiRule(new PiiOptions { Entities = [] });

        var result = await rule.EvaluateAsync(Context("write to john@example.com"));

        result.ModifiedText.Should().Be("write to <EMAIL_ADDRESS>");
    }
}
