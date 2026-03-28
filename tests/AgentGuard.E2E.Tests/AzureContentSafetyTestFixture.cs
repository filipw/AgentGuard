using AgentGuard.Azure.ContentSafety;
using AgentGuard.Core.Rules.ContentSafety;
using Azure;
using Azure.AI.ContentSafety;

namespace AgentGuard.E2E.Tests;

/// <summary>
/// Shared fixture that provides an <see cref="AzureContentSafetyClassifier"/> connected to a
/// user-supplied Azure Content Safety endpoint.
///
/// Required environment variables:
///   AZURE_CONTENT_SAFETY_ENDPOINT - Azure Content Safety endpoint URL
///   AZURE_CONTENT_SAFETY_KEY      - API key for the endpoint
/// </summary>
public sealed class AzureContentSafetyTestFixture : IDisposable
{
    public IContentSafetyClassifier? Classifier { get; }
    public bool IsAvailable { get; }
    public string SkipReason { get; }

    public AzureContentSafetyTestFixture()
    {
        var endpoint = Environment.GetEnvironmentVariable("AZURE_CONTENT_SAFETY_ENDPOINT");
        var key = Environment.GetEnvironmentVariable("AZURE_CONTENT_SAFETY_KEY");

        if (string.IsNullOrEmpty(endpoint) || string.IsNullOrEmpty(key))
        {
            IsAvailable = false;
            SkipReason = "Set AZURE_CONTENT_SAFETY_ENDPOINT and AZURE_CONTENT_SAFETY_KEY to run Azure Content Safety e2e tests.";
            return;
        }

        var client = new ContentSafetyClient(new Uri(endpoint), new AzureKeyCredential(key));
        Classifier = new AzureContentSafetyClassifier(client);
        IsAvailable = true;
        SkipReason = "";
    }

    public void Dispose() { }
}

/// <summary>
/// Skip fact attribute that checks for Azure Content Safety availability.
/// </summary>
[AttributeUsage(AttributeTargets.Method)]
public sealed class AzureContentSafetyFactAttribute : Xunit.FactAttribute
{
    public AzureContentSafetyFactAttribute()
    {
        var endpoint = Environment.GetEnvironmentVariable("AZURE_CONTENT_SAFETY_ENDPOINT");
        var key = Environment.GetEnvironmentVariable("AZURE_CONTENT_SAFETY_KEY");

        if (string.IsNullOrEmpty(endpoint) || string.IsNullOrEmpty(key))
            Skip = "Set AZURE_CONTENT_SAFETY_ENDPOINT and AZURE_CONTENT_SAFETY_KEY to run Azure Content Safety e2e tests.";
    }
}
