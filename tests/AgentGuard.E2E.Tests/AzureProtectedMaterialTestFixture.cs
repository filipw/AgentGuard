using AgentGuard.Azure.ProtectedMaterial;

namespace AgentGuard.E2E.Tests;

/// <summary>
/// Shared fixture that provides an <see cref="AzureProtectedMaterialClient"/> connected to a
/// user-supplied Azure Content Safety endpoint.
///
/// Required environment variables:
///   AZURE_CONTENT_SAFETY_ENDPOINT - Azure Content Safety endpoint URL
///   AZURE_CONTENT_SAFETY_KEY      - API key for the endpoint
/// </summary>
public sealed class AzureProtectedMaterialTestFixture : IDisposable
{
    public AzureProtectedMaterialClient? Client { get; }
    public bool IsAvailable { get; }

    public AzureProtectedMaterialTestFixture()
    {
        var endpoint = Environment.GetEnvironmentVariable("AZURE_CONTENT_SAFETY_ENDPOINT");
        var key = Environment.GetEnvironmentVariable("AZURE_CONTENT_SAFETY_KEY");

        if (string.IsNullOrEmpty(endpoint) || string.IsNullOrEmpty(key))
        {
            IsAvailable = false;
            return;
        }

        Client = new AzureProtectedMaterialClient(endpoint, key);
        IsAvailable = true;
    }

    public void Dispose() => Client?.Dispose();
}

/// <summary>
/// Skip fact attribute that checks for Azure Content Safety availability (used by Protected Material tests).
/// </summary>
[AttributeUsage(AttributeTargets.Method)]
public sealed class AzureProtectedMaterialFactAttribute : Xunit.FactAttribute
{
    public AzureProtectedMaterialFactAttribute()
    {
        var endpoint = Environment.GetEnvironmentVariable("AZURE_CONTENT_SAFETY_ENDPOINT");
        var key = Environment.GetEnvironmentVariable("AZURE_CONTENT_SAFETY_KEY");

        if (string.IsNullOrEmpty(endpoint) || string.IsNullOrEmpty(key))
            Skip = "Set AZURE_CONTENT_SAFETY_ENDPOINT and AZURE_CONTENT_SAFETY_KEY to run Azure Protected Material e2e tests.";
    }
}
