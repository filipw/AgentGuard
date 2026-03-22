using Microsoft.Extensions.AI;
using OpenAI;

namespace AgentGuard.E2E.Tests;

/// <summary>
/// Shared fixture that provides an <see cref="IChatClient"/> connected to a user-supplied
/// OpenAI-compatible endpoint. Tests that need an LLM use this fixture.
///
/// Required environment variables:
///   AGENTGUARD_LLM_ENDPOINT - base URL of the OpenAI-compatible API (e.g. http://localhost:1234/v1/)
///   AGENTGUARD_LLM_MODEL    - model name to use (e.g. openai/gpt-oss-20b, gpt-4o-mini)
///
/// Optional:
///   AGENTGUARD_LLM_KEY - API key (defaults to "unused" for local servers that don't require auth)
///   AGENTGUARD_LLM_MAX_TOKENS - max output tokens (defaults to 1000; increase for reasoning models)
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
        var endpoint = Environment.GetEnvironmentVariable("AGENTGUARD_LLM_ENDPOINT");
        var model = Environment.GetEnvironmentVariable("AGENTGUARD_LLM_MODEL");
        var key = Environment.GetEnvironmentVariable("AGENTGUARD_LLM_KEY") ?? "unused";
        var maxTokens = int.TryParse(Environment.GetEnvironmentVariable("AGENTGUARD_LLM_MAX_TOKENS"), out var mt) ? mt : 1000;

        if (string.IsNullOrEmpty(endpoint) || string.IsNullOrEmpty(model))
        {
            IsAvailable = false;
            SkipReason = "Set AGENTGUARD_LLM_ENDPOINT and AGENTGUARD_LLM_MODEL to run e2e LLM tests.";
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
        var endpoint = Environment.GetEnvironmentVariable("AGENTGUARD_LLM_ENDPOINT");
        var model = Environment.GetEnvironmentVariable("AGENTGUARD_LLM_MODEL");

        if (string.IsNullOrEmpty(endpoint) || string.IsNullOrEmpty(model))
            Skip = "Set AGENTGUARD_LLM_ENDPOINT and AGENTGUARD_LLM_MODEL to run e2e LLM tests.";
    }
}
