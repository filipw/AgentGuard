using Microsoft.Extensions.AI;
using OpenAI;

namespace AgentGuard.E2E.Tests;

/// <summary>
/// Shared fixture that provides an <see cref="IChatClient"/> connected to a user-supplied
/// OpenAI-compatible endpoint. Tests that need an LLM use this fixture.
///
/// Required environment variables:
///   OPENAI_BASE_URL - base URL of the OpenAI-compatible API (e.g. http://localhost:1234/v1/)
///   OPENAI_MODEL    - model name to use (e.g. openai/gpt-oss-20b, gpt-4o-mini)
///
/// Optional:
///   OPENAI_API_KEY - API key (defaults to "unused" for local servers that don't require auth)
///   OPENAI_MAX_TOKENS - max output tokens (defaults to 1000; increase for reasoning models)
/// </summary>
public sealed class LlmTestFixture : IDisposable
{
    public IChatClient? ChatClient { get; }
    public ChatOptions? ChatOptions { get; }
    public string? ModelName { get; }
    public bool IsAvailable { get; }
    public string SkipReason { get; }

    public LlmTestFixture()
    {
        var endpoint = Environment.GetEnvironmentVariable("OPENAI_BASE_URL");
        var model = Environment.GetEnvironmentVariable("OPENAI_MODEL");
        var key = Environment.GetEnvironmentVariable("OPENAI_API_KEY") ?? "unused";
        var maxTokens = int.TryParse(Environment.GetEnvironmentVariable("OPENAI_MAX_TOKENS"), out var mt) ? mt : 1000;

        if (string.IsNullOrEmpty(endpoint) || string.IsNullOrEmpty(model))
        {
            IsAvailable = false;
            SkipReason = "Set OPENAI_BASE_URL and OPENAI_MODEL to run e2e LLM tests.";
            return;
        }

        var client = new OpenAIClient(new System.ClientModel.ApiKeyCredential(key),
            new OpenAIClientOptions { Endpoint = new Uri(endpoint) });

        ChatClient = client.GetChatClient(model).AsIChatClient();
        ChatOptions = new ChatOptions { MaxOutputTokens = maxTokens, Temperature = 0f };
        ModelName = model;
        IsAvailable = true;
        SkipReason = "";
    }

    public void Dispose()
    {
        (ChatClient as IDisposable)?.Dispose();
    }
}

/// <summary>
/// Skip fact attribute that checks for LLM availability.
/// </summary>
[AttributeUsage(AttributeTargets.Method)]
public sealed class LlmFactAttribute : Xunit.FactAttribute
{
    public LlmFactAttribute()
    {
        var endpoint = Environment.GetEnvironmentVariable("OPENAI_BASE_URL");
        var model = Environment.GetEnvironmentVariable("OPENAI_MODEL");

        if (string.IsNullOrEmpty(endpoint) || string.IsNullOrEmpty(model))
            Skip = "Set OPENAI_BASE_URL and OPENAI_MODEL to run e2e LLM tests.";
    }
}
