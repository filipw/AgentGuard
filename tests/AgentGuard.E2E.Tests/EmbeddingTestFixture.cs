using Microsoft.Extensions.AI;
using OpenAI;

namespace AgentGuard.E2E.Tests;

/// <summary>
/// Shared fixture that provides an <see cref="IEmbeddingGenerator{TInput,TEmbedding}"/> connected to
/// a user-supplied OpenAI-compatible embedding endpoint. Tests that need embeddings use this fixture.
///
/// Required environment variables:
///   OPENAI_EMBEDDING_BASE_URL - base URL of the OpenAI-compatible API (e.g. http://localhost:1234/v1/)
///   OPENAI_EMBEDDING_MODEL    - embedding model name (e.g. jina-embeddings-v5-text-small-retrieval)
///
/// Optional:
///   OPENAI_EMBEDDING_KEY - API key (defaults to "unused" for local servers)
///
/// Falls back to OPENAI_BASE_URL / OPENAI_API_KEY if embedding-specific vars are not set,
/// since many local servers (LM Studio, Ollama) serve both chat and embedding on the same endpoint.
/// </summary>
public sealed class EmbeddingTestFixture : IDisposable
{
    public IEmbeddingGenerator<string, Embedding<float>>? EmbeddingGenerator { get; }
    public string? ModelName { get; }
    public bool IsAvailable { get; }
    public string SkipReason { get; }

    public EmbeddingTestFixture()
    {
        var endpoint = Environment.GetEnvironmentVariable("OPENAI_EMBEDDING_BASE_URL")
            ?? Environment.GetEnvironmentVariable("OPENAI_BASE_URL");
        var model = Environment.GetEnvironmentVariable("OPENAI_EMBEDDING_MODEL");
        var key = Environment.GetEnvironmentVariable("OPENAI_EMBEDDING_KEY")
            ?? Environment.GetEnvironmentVariable("OPENAI_API_KEY")
            ?? "unused";

        if (string.IsNullOrEmpty(endpoint) || string.IsNullOrEmpty(model))
        {
            IsAvailable = false;
            SkipReason = "Set OPENAI_EMBEDDING_BASE_URL (or OPENAI_BASE_URL) and OPENAI_EMBEDDING_MODEL to run embedding e2e tests.";
            return;
        }

        var client = new OpenAIClient(new System.ClientModel.ApiKeyCredential(key),
            new OpenAIClientOptions { Endpoint = new Uri(endpoint) });

        EmbeddingGenerator = client.GetEmbeddingClient(model).AsIEmbeddingGenerator();
        ModelName = model;
        IsAvailable = true;
        SkipReason = "";
    }

    public void Dispose()
    {
        (EmbeddingGenerator as IDisposable)?.Dispose();
    }
}

/// <summary>
/// Skip fact attribute that checks for embedding model availability.
/// </summary>
[AttributeUsage(AttributeTargets.Method)]
public sealed class EmbeddingFactAttribute : Xunit.FactAttribute
{
    public EmbeddingFactAttribute()
    {
        var endpoint = Environment.GetEnvironmentVariable("OPENAI_EMBEDDING_BASE_URL")
            ?? Environment.GetEnvironmentVariable("OPENAI_BASE_URL");
        var model = Environment.GetEnvironmentVariable("OPENAI_EMBEDDING_MODEL");

        if (string.IsNullOrEmpty(endpoint) || string.IsNullOrEmpty(model))
            Skip = "Set OPENAI_EMBEDDING_BASE_URL (or OPENAI_BASE_URL) and OPENAI_EMBEDDING_MODEL to run embedding e2e tests.";
    }
}
