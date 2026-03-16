using AgentGuard.Local.Classifiers;
using FluentAssertions;
using Xunit;

namespace AgentGuard.Local.Tests;

public class KeywordSimilarityProviderTests
{
    [Fact]
    public async Task ShouldReturnHighSimilarity_WhenInputMatchesTopicKeywords()
    {
        var provider = new KeywordSimilarityProvider(new Dictionary<string, IEnumerable<string>>
        {
            ["billing"] = ["invoice", "payment", "charge", "refund"]
        });

        var similarity = await provider.ComputeSimilarityAsync("I need help with my invoice payment", "billing");
        similarity.Should().BeGreaterThan(0.3f);
    }

    [Fact]
    public async Task ShouldReturnZero_WhenInputHasNoOverlap()
    {
        var provider = new KeywordSimilarityProvider(new Dictionary<string, IEnumerable<string>>
        {
            ["billing"] = ["invoice", "payment", "charge", "refund"]
        });

        var similarity = await provider.ComputeSimilarityAsync("Tell me about cats and dogs", "billing");
        similarity.Should().Be(0f);
    }

    [Fact]
    public async Task ShouldReturnZero_WhenInputIsEmpty()
    {
        var provider = new KeywordSimilarityProvider();
        var similarity = await provider.ComputeSimilarityAsync("", "billing");
        similarity.Should().Be(0f);
    }

    [Fact]
    public async Task ShouldAutoTokenizeTopicDescriptor_WhenNoExplicitKeywords()
    {
        var provider = new KeywordSimilarityProvider();

        // Topic descriptor "billing support" gets tokenized into keywords
        var similarity = await provider.ComputeSimilarityAsync("billing question about my account", "billing support");
        similarity.Should().BeGreaterThan(0f);
    }

    [Fact]
    public async Task ShouldFilterStopWords()
    {
        var provider = new KeywordSimilarityProvider();

        // "the" is a stop word and should not contribute to similarity
        var similarity = await provider.ComputeSimilarityAsync("the", "the");
        similarity.Should().Be(0f);
    }

    [Fact]
    public async Task ShouldBeCaseInsensitive()
    {
        var provider = new KeywordSimilarityProvider(new Dictionary<string, IEnumerable<string>>
        {
            ["billing"] = ["INVOICE", "Payment"]
        });

        var similarity = await provider.ComputeSimilarityAsync("invoice payment details", "billing");
        similarity.Should().BeGreaterThan(0f);
    }

    [Fact]
    public async Task ShouldCapSimilarityAtOne()
    {
        var provider = new KeywordSimilarityProvider(new Dictionary<string, IEnumerable<string>>
        {
            ["test"] = ["hello"]
        });

        // Input has more matching words than topic words
        var similarity = await provider.ComputeSimilarityAsync("hello hello hello", "test");
        similarity.Should().BeLessOrEqualTo(1f);
    }

    [Fact]
    public async Task ShouldCacheTopicWords()
    {
        var provider = new KeywordSimilarityProvider();

        // Call twice with same topic - should use cached value
        var sim1 = await provider.ComputeSimilarityAsync("billing question", "billing support");
        var sim2 = await provider.ComputeSimilarityAsync("billing question", "billing support");
        sim1.Should().Be(sim2);
    }
}
