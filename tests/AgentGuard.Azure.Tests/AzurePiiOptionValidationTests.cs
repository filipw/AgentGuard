using AgentGuard.Azure.Pii;
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

    private static AzurePiiOptions Options(double? threshold) => new()
    {
        Endpoint = "https://my-resource.cognitiveservices.azure.com",
        SubscriptionKey = "key",
        SupportedEntities = [PiiEntities.Person],
        ConfidenceThreshold = threshold
    };
}
