using AgentGuard.Core.Builders;
using Microsoft.Extensions.Logging;

namespace AgentGuard.RemoteClassifier;

/// <summary>
/// Extension methods for adding remote classifier guardrail rules to the policy builder.
/// </summary>
public static class RemoteClassifierBuilderExtensions
{
    /// <summary>
    /// Adds remote ML-based prompt injection detection (order 13) using a pre-configured classifier.
    /// Runs between ONNX (order 12) and LLM (order 15).
    /// </summary>
    /// <param name="builder">The policy builder.</param>
    /// <param name="classifier">The remote classifier to use.</param>
    /// <param name="options">Optional configuration.</param>
    /// <param name="logger">Optional logger.</param>
    /// <returns>The builder for chaining.</returns>
    public static GuardrailPolicyBuilder BlockPromptInjectionWithRemoteClassifier(
        this GuardrailPolicyBuilder builder,
        IRemoteClassifier classifier,
        RemotePromptInjectionOptions? options = null,
        ILogger<RemotePromptInjectionRule>? logger = null)
    {
        builder.AddRule(new RemotePromptInjectionRule(classifier, options, logger));
        return builder;
    }

    /// <summary>
    /// Adds remote ML-based prompt injection detection (order 13) using an HTTP classifier endpoint.
    /// Supports HuggingFace text-classification format (default) and custom simple format.
    /// </summary>
    /// <param name="builder">The policy builder.</param>
    /// <param name="endpointUrl">URL of the classification endpoint (e.g. "http://localhost:8000/classify").</param>
    /// <param name="apiKey">Optional API key for authenticated endpoints.</param>
    /// <param name="modelName">Optional model name for metadata (e.g. "sentinel-v2").</param>
    /// <param name="threshold">Confidence threshold (0.0–1.0). Default: 0.5.</param>
    /// <returns>The builder for chaining.</returns>
    public static GuardrailPolicyBuilder BlockPromptInjectionWithRemoteClassifier(
        this GuardrailPolicyBuilder builder,
        string endpointUrl,
        string? apiKey = null,
        string? modelName = null,
        float threshold = 0.5f)
    {
        var classifier = new HttpClassifier(new HttpClassifierOptions
        {
            EndpointUrl = endpointUrl,
            ApiKey = apiKey,
            ModelName = modelName
        });

        builder.AddRule(new RemotePromptInjectionRule(classifier, new RemotePromptInjectionOptions
        {
            Threshold = threshold
        }));

        return builder;
    }

    /// <summary>
    /// Adds remote ML-based prompt injection detection (order 13) using an HttpClient from DI
    /// (e.g. via IHttpClientFactory). Useful for configuring retries, timeouts, and other
    /// HttpClient options via the standard .NET HTTP pipeline.
    /// </summary>
    /// <param name="builder">The policy builder.</param>
    /// <param name="httpClient">Pre-configured HttpClient instance.</param>
    /// <param name="classifierOptions">HTTP classifier endpoint configuration.</param>
    /// <param name="ruleOptions">Optional rule configuration.</param>
    /// <param name="logger">Optional logger.</param>
    /// <returns>The builder for chaining.</returns>
    public static GuardrailPolicyBuilder BlockPromptInjectionWithRemoteClassifier(
        this GuardrailPolicyBuilder builder,
        HttpClient httpClient,
        HttpClassifierOptions classifierOptions,
        RemotePromptInjectionOptions? ruleOptions = null,
        ILogger<RemotePromptInjectionRule>? logger = null)
    {
        var classifier = new HttpClassifier(httpClient, classifierOptions);
        builder.AddRule(new RemotePromptInjectionRule(classifier, ruleOptions, logger));
        return builder;
    }
}
