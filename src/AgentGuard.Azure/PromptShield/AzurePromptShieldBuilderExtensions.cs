using AgentGuard.Core.Builders;
using Microsoft.Extensions.Logging;

namespace AgentGuard.Azure.PromptShield;

/// <summary>
/// Extension methods for adding Azure Prompt Shield guardrail rules to the policy builder.
/// </summary>
public static class AzurePromptShieldBuilderExtensions
{
    /// <summary>
    /// Adds Azure Prompt Shield-based prompt injection detection (order 14).
    /// Detects user prompt attacks (jailbreaks) and optionally document attacks (indirect injection).
    /// Runs between remote ML classifiers (order 13) and LLM-as-judge (order 15).
    /// </summary>
    /// <param name="builder">The policy builder.</param>
    /// <param name="client">Pre-configured Prompt Shield client.</param>
    /// <param name="options">Optional configuration (e.g. enable document analysis).</param>
    /// <returns>The builder for chaining.</returns>
    public static GuardrailPolicyBuilder BlockPromptInjectionWithAzurePromptShield(
        this GuardrailPolicyBuilder builder,
        AzurePromptShieldClient client,
        AzurePromptShieldOptions? options = null)
    {
        builder.AddRule(new AzurePromptShieldRule(client, options));
        return builder;
    }

    /// <summary>
    /// Adds Azure Prompt Shield-based prompt injection detection (order 14) with endpoint configuration.
    /// </summary>
    /// <param name="builder">The policy builder.</param>
    /// <param name="endpoint">Azure Content Safety endpoint URL.</param>
    /// <param name="apiKey">API key for the Content Safety resource.</param>
    /// <param name="options">Optional configuration.</param>
    /// <param name="logger">Optional logger.</param>
    /// <returns>The builder for chaining.</returns>
    public static GuardrailPolicyBuilder BlockPromptInjectionWithAzurePromptShield(
        this GuardrailPolicyBuilder builder,
        string endpoint,
        string apiKey,
        AzurePromptShieldOptions? options = null,
        ILogger<AzurePromptShieldClient>? logger = null)
    {
        var client = new AzurePromptShieldClient(endpoint, apiKey, logger: logger);
        builder.AddRule(new AzurePromptShieldRule(client, options));
        return builder;
    }
}
