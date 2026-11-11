using AgentGuard.Azure.Pii;
using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Builders;
using FluentAssertions;
using TasmanianDevil;
using TasmanianDevil.Azure;
using Xunit;

namespace AgentGuard.Azure.Tests;

public class AzurePiiOptionValidationTests
{
    [Theory]
    [InlineData(double.NaN)]
    [InlineData(1.5)]
    [InlineData(-0.1)]
    [InlineData(double.PositiveInfinity)]
    public void ShouldThrow_WhenConfidenceThresholdIsNotANumberBetweenZeroAndOne(double threshold)
    {
        var act = () => new GuardrailPolicyBuilder().RedactPiiWithAzure(Options(threshold));

        act.Should().Throw<ArgumentOutOfRangeException>().WithMessage("*ConfidenceThreshold*");
    }

    [Fact]
    public void ShouldThrow_WhenConfidenceThresholdIsNaNAndAClientIsSupplied()
    {
        using var httpClient = new HttpClient();
        var client = new AzurePiiClient(httpClient, Options(threshold: null));

        var act = () => new GuardrailPolicyBuilder().RedactPiiWithAzure(client, Options(double.NaN));

        act.Should().Throw<ArgumentOutOfRangeException>().WithMessage("*ConfidenceThreshold*");
    }

    [Theory]
    [InlineData(null)]
    [InlineData(0.0)]
    [InlineData(0.8)]
    [InlineData(1.0)]
    public void ShouldAddTheRule_WhenConfidenceThresholdIsUnsetOrBetweenZeroAndOne(double? threshold)
    {
        var policy = new GuardrailPolicyBuilder().RedactPiiWithAzure(Options(threshold)).Build();

        policy.Rules.Should().ContainSingle().Which.Name.Should().Be("pii");
        (policy as IDisposable)?.Dispose();
    }

    // a name Azure never returns would leave the rule asking for nothing

    [Theory]
    [InlineData("EMAIL_ADRESS")]
    [InlineData("PERSN")]
    [InlineData("")]
    public void ShouldThrow_WhenASupportedEntityIsNotSomethingAzureDetects(string entity)
    {
        var act = () => new GuardrailPolicyBuilder().RedactPiiWithAzure(Options([PiiEntities.Person, entity]));

        act.Should().Throw<ArgumentException>()
            .WithMessage($"*'{entity}'*{PiiEntities.EmailAddress}*{PiiEntities.Person}*Email (for {PiiEntities.EmailAddress})*");
    }

    [Fact]
    public void ShouldThrow_WhenASupportedEntityIsNotSomethingAzureDetectsAndAClientIsSupplied()
    {
        using var httpClient = new HttpClient();
        var client = new AzurePiiClient(httpClient, Options(threshold: null));

        var act = () => new GuardrailPolicyBuilder().RedactPiiWithAzure(client, Options(["PERSN"]));

        act.Should().Throw<ArgumentException>().WithMessage("*'PERSN'*");
    }

    [Fact]
    public void ShouldThrow_WhenNoSupportedEntitiesAreGiven()
    {
        var act = () => new GuardrailPolicyBuilder().RedactPiiWithAzure(Options([]));

        act.Should().Throw<ArgumentException>().WithMessage("*SupportedEntities*");
    }

    [Fact]
    public void ShouldThrow_WhenASupportedEntityIsALocalOnlyEntityType()
    {
        // the engine knows CRYPTO, but no Azure category maps to it, so Azure would never return it
        var act = () => new GuardrailPolicyBuilder().RedactPiiWithAzure(Options([PiiEntities.Crypto]));

        act.Should().Throw<ArgumentException>().WithMessage($"*'{PiiEntities.Crypto}'*");
    }

    [Theory]
    [InlineData("PERSON")]
    [InlineData("person")]
    [InlineData("Person")]
    [InlineData(" Person ")]
    public async Task ShouldDetectThePerson_WhenTheEntityIsGivenInTheEngineOrTheAzureSpelling(string entity)
    {
        const string text = "John Smith called";
        var options = Options([entity]);
        var handler = new LambdaHttpHandler((_, _) => Task.FromResult(LambdaHttpHandler.Json(
            """
            { "results": { "documents": [ { "id": "1", "entities": [
                { "text": "John Smith", "category": "Person", "offset": 0, "length": 10, "confidenceScore": 0.95 }
            ] } ], "errors": [] } }
            """)));
        var rule = new GuardrailPolicyBuilder()
            .RedactPiiWithAzure(new AzurePiiClient(new HttpClient(handler), options), options)
            .Build()
            .Rules.Single();

        var result = await rule.EvaluateAsync(new GuardrailContext { Text = text, Phase = GuardrailPhase.Input });

        result.ModifiedText.Should().Be("<PERSON> called");
    }

    [Fact]
    public void ShouldAcceptACategoryNameOfACustomCategoryMap()
    {
        var options = new AzurePiiOptions
        {
            Endpoint = "https://my-resource.cognitiveservices.azure.com",
            SubscriptionKey = "key",
            SupportedEntities = ["usdriverslicensenumber", "LICENCE"],
            CategoryMap = new Dictionary<string, string> { ["USDriversLicenseNumber"] = "LICENCE" },
        };

        var policy = new GuardrailPolicyBuilder().RedactPiiWithAzure(options).Build();

        policy.Rules.Should().ContainSingle();
        (policy as IDisposable)?.Dispose();
    }

    [Fact]
    public void ShouldAcceptAnUnmappedAzureCategory_WhenItIsAmongTheRequestedCategories()
    {
        var options = new AzurePiiOptions
        {
            Endpoint = "https://my-resource.cognitiveservices.azure.com",
            SubscriptionKey = "key",
            SupportedEntities = ["USDriversLicenseNumber"],
            PiiCategories = ["USDriversLicenseNumber"],
        };

        var policy = new GuardrailPolicyBuilder().RedactPiiWithAzure(options).Build();

        policy.Rules.Should().ContainSingle();
        (policy as IDisposable)?.Dispose();
    }

    private static AzurePiiOptions Options(IReadOnlyList<string> entities) => new()
    {
        Endpoint = "https://my-resource.cognitiveservices.azure.com",
        SubscriptionKey = "key",
        SupportedEntities = entities,
    };

    private static AzurePiiOptions Options(double? threshold) => new()
    {
        Endpoint = "https://my-resource.cognitiveservices.azure.com",
        SubscriptionKey = "key",
        SupportedEntities = [PiiEntities.Person],
        ConfidenceThreshold = threshold
    };
}
