using AgentGuard.Azure.PromptShield;

namespace AgentGuard.E2E.Tests;

/// <summary>
/// Shared fixture that provides an <see cref="AzurePromptShieldClient"/> connected to a
/// user-supplied Azure Content Safety endpoint.
///
/// Required environment variables:
///   AZURE_CONTENT_SAFETY_ENDPOINT - Azure Content Safety endpoint URL
///   AZURE_CONTENT_SAFETY_KEY      - API key for the endpoint
/// </summary>
public sealed class AzurePromptShieldTestFixture : IDisposable
{
    public AzurePromptShieldClient? Client { get; }
    public bool IsAvailable { get; }

    public AzurePromptShieldTestFixture()
    {
        var endpoint = Environment.GetEnvironmentVariable("AZURE_CONTENT_SAFETY_ENDPOINT");
        var key = Environment.GetEnvironmentVariable("AZURE_CONTENT_SAFETY_KEY");

        if (string.IsNullOrEmpty(endpoint) || string.IsNullOrEmpty(key))
        {
            IsAvailable = false;
            return;
        }

        Client = new AzurePromptShieldClient(endpoint, key);
        IsAvailable = true;
    }

    public void Dispose() => Client?.Dispose();
}

/// <summary>
/// Skip fact attribute that checks for Azure Content Safety availability (used by Prompt Shield tests).
/// </summary>
[AttributeUsage(AttributeTargets.Method)]
public sealed class AzurePromptShieldFactAttribute : Xunit.FactAttribute
{
    public AzurePromptShieldFactAttribute()
    {
        var endpoint = Environment.GetEnvironmentVariable("AZURE_CONTENT_SAFETY_ENDPOINT");
        var key = Environment.GetEnvironmentVariable("AZURE_CONTENT_SAFETY_KEY");

        if (string.IsNullOrEmpty(endpoint) || string.IsNullOrEmpty(key))
            Skip = "Set AZURE_CONTENT_SAFETY_ENDPOINT and AZURE_CONTENT_SAFETY_KEY to run Azure Prompt Shield e2e tests.";
    }
}
