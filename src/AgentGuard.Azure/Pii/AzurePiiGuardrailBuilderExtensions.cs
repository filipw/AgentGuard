using AgentGuard.Core.Builders;
using AgentGuard.Pii;
using Azure.Core;
using TasmanianDevil;
using TasmanianDevil.Analyzer;
using TasmanianDevil.Analyzer.Context;
using TasmanianDevil.Azure;

namespace AgentGuard.Azure.Pii;

/// <summary>
/// Extension methods for adding Azure AI Language PII detection to the policy builder.
/// </summary>
public static class AzurePiiGuardrailBuilderExtensions
{
    private const string CognitiveServicesScope = "https://cognitiveservices.azure.com/.default";

    /// <summary>
    /// Adds PII redaction (order 20) augmented with Azure AI Language's PII entity recognition -
    /// native <c>Person</c> and full street <c>Address</c> categories that the offline regex/GLiNER
    /// recognizers can't match. The Azure service is a detector only: it returns entity spans, which
    /// flow through the same local <c>AnonymizerEngine</c> as the regex/checksum entities, so
    /// anonymization, reversible encrypt/decrypt, and conflict resolution keep working unchanged.
    /// <para>
    /// PRIVACY: this sends the raw, unredacted analyzed text to Azure. <c>loggingOptOut</c> defaults
    /// to <c>true</c> on <see cref="AzurePiiOptions"/> so Azure does not retain it - see docs/remote-pii.md.
    /// </para>
    /// </summary>
    /// <param name="builder">The policy builder.</param>
    /// <param name="azureOptions">Azure PII detector configuration (endpoint, auth, supported entities, domain, timeout, fail-open).</param>
    /// <param name="piiOptions">Optional PII detection/anonymization configuration (entities, countries, operators).</param>
    /// <returns>The builder for chaining.</returns>
    public static GuardrailPolicyBuilder RedactPiiWithAzure(
        this GuardrailPolicyBuilder builder,
        AzurePiiOptions azureOptions,
        PiiOptions? piiOptions = null)
    {
        ArgumentNullException.ThrowIfNull(azureOptions);
        return builder.RedactPiiWithAzure(new AzurePiiClient(azureOptions), azureOptions, piiOptions);
    }

    /// <summary>
    /// Adds PII redaction (order 20) augmented with Azure AI Language, using a pre-configured
    /// <see cref="AzurePiiClient"/> (e.g. one built over a shared <see cref="HttpClient"/>).
    /// </summary>
    /// <param name="builder">The policy builder.</param>
    /// <param name="client">The Azure PII client to delegate to.</param>
    /// <param name="azureOptions">Azure PII detector configuration (supported entities, timeout, fail-open, category map).</param>
    /// <param name="piiOptions">Optional PII detection/anonymization configuration.</param>
    /// <returns>The builder for chaining.</returns>
    public static GuardrailPolicyBuilder RedactPiiWithAzure(
        this GuardrailPolicyBuilder builder,
        AzurePiiClient client,
        AzurePiiOptions azureOptions,
        PiiOptions? piiOptions = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(azureOptions);

        // resolve the analysis language the same way PiiRule will (piiOptions?.Language ?? "en") and pin
        // the recognizer to it, so the registry never filters the Azure recognizer out on a mismatch.
        var language = piiOptions?.Language ?? "en";
        var registry = PiiRecognizers.CreateRegistry(language, piiOptions?.Countries);
        registry.AddRecognizer(new AzurePiiRecognizer(client, azureOptions, supportedLanguage: language));

        // defaultScoreThreshold 0 here; PiiRule applies PiiOptions.ScoreThreshold per evaluation.
        var engine = new AnalyzerEngine(
            registry,
            new LemmaContextAwareEnhancer(contextMatchingMode: piiOptions?.ContextMatchingMode ?? ContextMatchingMode.Substring),
            defaultScoreThreshold: 0);

        builder.AddRule(new PiiRule(piiOptions, analyzer: engine));
        return builder;
    }

    /// <summary>
    /// Adds PII redaction augmented with Azure AI Language, authenticating via Azure AD
    /// (e.g. <c>DefaultAzureCredential</c>) instead of a subscription key. This is the only place
    /// <c>TasmanianDevil.Azure</c>'s dependency-free <c>TokenProvider</c> delegate is bound to a
    /// concrete <see cref="TokenCredential"/> - <c>TasmanianDevil.Azure</c> itself has no
    /// <c>Azure.Identity</c> dependency.
    /// </summary>
    /// <param name="builder">The policy builder.</param>
    /// <param name="endpoint">The Azure AI Language resource endpoint.</param>
    /// <param name="credential">The Azure AD credential (e.g. <c>new DefaultAzureCredential()</c>).</param>
    /// <param name="entities">The canonical entity types to detect (e.g. <c>[PiiEntities.Person, PiiEntities.Address]</c>).</param>
    /// <param name="piiOptions">Optional PII detection/anonymization configuration.</param>
    /// <returns>The builder for chaining.</returns>
    public static GuardrailPolicyBuilder RedactPiiWithAzure(
        this GuardrailPolicyBuilder builder,
        string endpoint,
        TokenCredential credential,
        IReadOnlyList<string> entities,
        PiiOptions? piiOptions = null)
    {
        ArgumentNullException.ThrowIfNull(credential);

        var azureOptions = new AzurePiiOptions
        {
            Endpoint = endpoint,
            SupportedEntities = entities,
            TokenProvider = async ct =>
            {
                var token = await credential.GetTokenAsync(new TokenRequestContext([CognitiveServicesScope]), ct).ConfigureAwait(false);
                return token.Token;
            },
        };

        return builder.RedactPiiWithAzure(azureOptions, piiOptions);
    }

    /// <summary>
    /// Shorthand: adds PII redaction augmented with Azure AI Language, authenticating with a
    /// subscription key. Use the <see cref="AzurePiiOptions"/> overload for domain (PHI), a
    /// confidence threshold, or a category map override.
    /// </summary>
    /// <param name="builder">The policy builder.</param>
    /// <param name="endpoint">The Azure AI Language resource endpoint.</param>
    /// <param name="subscriptionKey">API key for the Azure AI Language resource.</param>
    /// <param name="entities">The canonical entity types to detect (e.g. <c>[PiiEntities.Person, PiiEntities.Address]</c>).</param>
    /// <param name="piiOptions">Optional PII detection/anonymization configuration.</param>
    /// <returns>The builder for chaining.</returns>
    public static GuardrailPolicyBuilder RedactPiiWithAzure(
        this GuardrailPolicyBuilder builder,
        string endpoint,
        string subscriptionKey,
        IReadOnlyList<string> entities,
        PiiOptions? piiOptions = null)
    {
        return builder.RedactPiiWithAzure(
            new AzurePiiOptions { Endpoint = endpoint, SubscriptionKey = subscriptionKey, SupportedEntities = entities },
            piiOptions);
    }
}
