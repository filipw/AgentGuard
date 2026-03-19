using System.Collections.Concurrent;
using AgentGuard.Core.Rules.TopicBoundary;
using Microsoft.Extensions.AI;

namespace AgentGuard.Local.Classifiers;

/// <summary>
/// Embedding-based similarity provider for topic boundary enforcement.
/// Uses <see cref="IEmbeddingGenerator{TInput,TEmbedding}"/> to compute cosine similarity
/// between user input and topic descriptors. Topic embeddings are cached for efficiency.
/// </summary>
public sealed class EmbeddingSimilarityProvider : ITopicSimilarityProvider
{
    private readonly IEmbeddingGenerator<string, Embedding<float>> _generator;
    private readonly ConcurrentDictionary<string, Lazy<Task<Embedding<float>>>> _topicCache = new(StringComparer.OrdinalIgnoreCase);

    public EmbeddingSimilarityProvider(IEmbeddingGenerator<string, Embedding<float>> generator)
    {
        _generator = generator ?? throw new ArgumentNullException(nameof(generator));
    }

    public async ValueTask<float> ComputeSimilarityAsync(
        string input, string topicDescriptor, CancellationToken cancellationToken = default)
    {
        var topicEmbedding = await GetOrComputeTopicEmbeddingAsync(topicDescriptor, cancellationToken);
        var inputResult = await _generator.GenerateAsync([input], cancellationToken: cancellationToken);
        var inputEmbedding = inputResult[0];
        return CosineSimilarity(inputEmbedding.Vector.Span, topicEmbedding.Vector.Span);
    }

    private Task<Embedding<float>> GetOrComputeTopicEmbeddingAsync(string topicDescriptor, CancellationToken cancellationToken)
    {
        var lazy = _topicCache.GetOrAdd(topicDescriptor, key =>
            new Lazy<Task<Embedding<float>>>(async () =>
            {
                var result = await _generator.GenerateAsync([key], cancellationToken: cancellationToken);
                return result[0];
            }));
        return lazy.Value;
    }

    internal static float CosineSimilarity(ReadOnlySpan<float> a, ReadOnlySpan<float> b)
    {
        if (a.Length != b.Length || a.Length == 0) return 0f;

        float dot = 0f, normA = 0f, normB = 0f;
        for (var i = 0; i < a.Length; i++)
        {
            dot += a[i] * b[i];
            normA += a[i] * a[i];
            normB += b[i] * b[i];
        }

        if (normA == 0f || normB == 0f) return 0f;

        var similarity = dot / (MathF.Sqrt(normA) * MathF.Sqrt(normB));
        return Math.Max(similarity, 0f); // Clamp negatives to 0
    }
}
