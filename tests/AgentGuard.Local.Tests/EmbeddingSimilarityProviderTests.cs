using AgentGuard.Local.Classifiers;
using FluentAssertions;
using Microsoft.Extensions.AI;
using Moq;
using Xunit;

namespace AgentGuard.Local.Tests;

public class EmbeddingSimilarityProviderTests
{
    private static GeneratedEmbeddings<Embedding<float>> CreateEmbeddings(params float[][] vectors) =>
        new(vectors.Select(v => new Embedding<float>(v)).ToList());

    [Fact]
    public async Task ShouldReturnHighSimilarity_WhenEmbeddingsAreParallel()
    {
        var mock = new Mock<IEmbeddingGenerator<string, Embedding<float>>>();
        // Topic embedding
        mock.Setup(g => g.GenerateAsync(It.Is<IEnumerable<string>>(s => s.First() == "billing"), It.IsAny<EmbeddingGenerationOptions?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(CreateEmbeddings([1f, 0f, 0f]));
        // Input embedding - same direction
        mock.Setup(g => g.GenerateAsync(It.Is<IEnumerable<string>>(s => s.First() == "invoice question"), It.IsAny<EmbeddingGenerationOptions?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(CreateEmbeddings([2f, 0f, 0f]));

        var provider = new EmbeddingSimilarityProvider(mock.Object);
        var similarity = await provider.ComputeSimilarityAsync("invoice question", "billing");

        similarity.Should().BeApproximately(1.0f, 0.001f, "parallel vectors should have cosine similarity of 1");
    }

    [Fact]
    public async Task ShouldReturnZero_WhenEmbeddingsAreOrthogonal()
    {
        var mock = new Mock<IEmbeddingGenerator<string, Embedding<float>>>();
        mock.Setup(g => g.GenerateAsync(It.Is<IEnumerable<string>>(s => s.First() == "billing"), It.IsAny<EmbeddingGenerationOptions?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(CreateEmbeddings([1f, 0f, 0f]));
        mock.Setup(g => g.GenerateAsync(It.Is<IEnumerable<string>>(s => s.First() == "unrelated"), It.IsAny<EmbeddingGenerationOptions?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(CreateEmbeddings([0f, 1f, 0f]));

        var provider = new EmbeddingSimilarityProvider(mock.Object);
        var similarity = await provider.ComputeSimilarityAsync("unrelated", "billing");

        similarity.Should().BeApproximately(0f, 0.001f, "orthogonal vectors should have cosine similarity of 0");
    }

    [Fact]
    public async Task ShouldClampNegativeSimilarityToZero()
    {
        var mock = new Mock<IEmbeddingGenerator<string, Embedding<float>>>();
        mock.Setup(g => g.GenerateAsync(It.Is<IEnumerable<string>>(s => s.First() == "billing"), It.IsAny<EmbeddingGenerationOptions?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(CreateEmbeddings([1f, 0f, 0f]));
        mock.Setup(g => g.GenerateAsync(It.Is<IEnumerable<string>>(s => s.First() == "opposite"), It.IsAny<EmbeddingGenerationOptions?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(CreateEmbeddings([-1f, 0f, 0f]));

        var provider = new EmbeddingSimilarityProvider(mock.Object);
        var similarity = await provider.ComputeSimilarityAsync("opposite", "billing");

        similarity.Should().Be(0f, "negative cosine similarity should be clamped to 0");
    }

    [Fact]
    public async Task ShouldCacheTopicEmbeddings()
    {
        var mock = new Mock<IEmbeddingGenerator<string, Embedding<float>>>();
        mock.Setup(g => g.GenerateAsync(It.Is<IEnumerable<string>>(s => s.First() == "billing"), It.IsAny<EmbeddingGenerationOptions?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(CreateEmbeddings([1f, 0f, 0f]));
        mock.Setup(g => g.GenerateAsync(It.Is<IEnumerable<string>>(s => s.First() != "billing"), It.IsAny<EmbeddingGenerationOptions?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(CreateEmbeddings([0.8f, 0.2f, 0f]));

        var provider = new EmbeddingSimilarityProvider(mock.Object);

        // Call twice with same topic
        await provider.ComputeSimilarityAsync("question 1", "billing");
        await provider.ComputeSimilarityAsync("question 2", "billing");

        // Topic embedding should only be computed once
        mock.Verify(g => g.GenerateAsync(
            It.Is<IEnumerable<string>>(s => s.First() == "billing"),
            It.IsAny<EmbeddingGenerationOptions?>(),
            It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task ShouldNotCacheInputEmbeddings()
    {
        var mock = new Mock<IEmbeddingGenerator<string, Embedding<float>>>();
        mock.Setup(g => g.GenerateAsync(It.IsAny<IEnumerable<string>>(), It.IsAny<EmbeddingGenerationOptions?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(CreateEmbeddings([1f, 0f, 0f]));

        var provider = new EmbeddingSimilarityProvider(mock.Object);

        await provider.ComputeSimilarityAsync("input 1", "billing");
        await provider.ComputeSimilarityAsync("input 2", "billing");

        // 1 call for topic (cached) + 2 calls for different inputs = 3 total
        mock.Verify(g => g.GenerateAsync(
            It.IsAny<IEnumerable<string>>(),
            It.IsAny<EmbeddingGenerationOptions?>(),
            It.IsAny<CancellationToken>()), Times.Exactly(3));
    }

    [Fact]
    public void CosineSimilarity_ShouldReturnZero_ForZeroVectors()
    {
        var result = EmbeddingSimilarityProvider.CosineSimilarity(
            new float[] { 0f, 0f, 0f },
            new float[] { 0f, 0f, 0f });

        result.Should().Be(0f, "zero vectors should return 0 without NaN");
    }

    [Fact]
    public void CosineSimilarity_ShouldReturnZero_ForEmptyVectors()
    {
        var result = EmbeddingSimilarityProvider.CosineSimilarity(
            ReadOnlySpan<float>.Empty,
            ReadOnlySpan<float>.Empty);

        result.Should().Be(0f);
    }

    [Fact]
    public void CosineSimilarity_ShouldReturnZero_ForMismatchedLengths()
    {
        var result = EmbeddingSimilarityProvider.CosineSimilarity(
            new float[] { 1f, 0f },
            new float[] { 1f, 0f, 0f });

        result.Should().Be(0f, "mismatched vector lengths should return 0");
    }
}
