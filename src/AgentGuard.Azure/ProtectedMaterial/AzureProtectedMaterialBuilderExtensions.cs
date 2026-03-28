using AgentGuard.Core.Builders;
using Microsoft.Extensions.Logging;

namespace AgentGuard.Azure.ProtectedMaterial;

/// <summary>
/// Extension methods for adding Azure Protected Material detection guardrail rules to the policy builder.
/// </summary>
public static class AzureProtectedMaterialBuilderExtensions
{
    /// <summary>
    /// Adds Azure Protected Material detection for LLM output (order 76).
    /// Detects copyrighted text (lyrics, articles, recipes) and optionally code from GitHub repositories.
    /// Runs after LLM copyright rule (order 75) as a complementary cloud-based check.
    /// </summary>
    /// <param name="builder">The policy builder.</param>
    /// <param name="client">Pre-configured Protected Material client.</param>
    /// <param name="options">Optional configuration (e.g. enable code analysis, warn vs block).</param>
    /// <returns>The builder for chaining.</returns>
    public static GuardrailPolicyBuilder BlockProtectedMaterialWithAzure(
        this GuardrailPolicyBuilder builder,
        AzureProtectedMaterialClient client,
        AzureProtectedMaterialOptions? options = null)
    {
        builder.AddRule(new AzureProtectedMaterialRule(client, options));
        return builder;
    }

    /// <summary>
    /// Adds Azure Protected Material detection for LLM output (order 76) with endpoint configuration.
    /// </summary>
    /// <param name="builder">The policy builder.</param>
    /// <param name="endpoint">Azure Content Safety endpoint URL.</param>
    /// <param name="apiKey">API key for the Content Safety resource.</param>
    /// <param name="options">Optional configuration.</param>
    /// <param name="logger">Optional logger.</param>
    /// <returns>The builder for chaining.</returns>
    public static GuardrailPolicyBuilder BlockProtectedMaterialWithAzure(
        this GuardrailPolicyBuilder builder,
        string endpoint,
        string apiKey,
        AzureProtectedMaterialOptions? options = null,
        ILogger<AzureProtectedMaterialClient>? logger = null)
    {
        var client = new AzureProtectedMaterialClient(endpoint, apiKey, logger: logger);
        builder.AddRule(new AzureProtectedMaterialRule(client, options));
        return builder;
    }
}
