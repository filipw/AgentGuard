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

    // the service rejects a synchronous-call document over 5,120 text elements, so longer text is
    // analyzed in windows. A UTF-16 code unit count is never below the text element count, so
    // windows of 5,000 code units always fit, and a 500-unit overlap keeps a name or address that
    // straddles a window boundary whole in one of them.
    private const int MaxChunkLength = 5_000;
    private const int ChunkOverlap = 500;

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
    /// <para>
    /// Text over the service's 5,120-character document limit is analyzed in overlapping windows of
    /// at most 5,000 characters, one call at a time, each subject to <see cref="AzurePiiOptions.Timeout"/>
    /// and <see cref="AzurePiiOptions.FailOpen"/>; the spans are mapped back onto the full text.
    /// </para>
    /// </summary>
    /// <param name="builder">The policy builder.</param>
    /// <param name="azureOptions">Azure PII detector configuration (endpoint, auth, supported entities, domain, timeout, fail-open).</param>
    /// <param name="piiOptions">Optional PII detection/anonymization configuration (entities, countries, operators).</param>
    /// <returns>The builder for chaining.</returns>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <see cref="AzurePiiOptions.ConfidenceThreshold"/> is NaN or outside 0.0-1.0.</exception>
    public static GuardrailPolicyBuilder RedactPiiWithAzure(
        this GuardrailPolicyBuilder builder,
        AzurePiiOptions azureOptions,
        PiiOptions? piiOptions = null)
    {
        ArgumentNullException.ThrowIfNull(azureOptions);
        ValidateConfidenceThreshold(azureOptions);
        return builder.RedactPiiWithAzure(new AzurePiiClient(azureOptions), azureOptions, piiOptions);
    }

    /// <summary>
    /// Adds PII redaction (order 20) augmented with Azure AI Language, using a pre-configured
    /// <see cref="AzurePiiClient"/> (e.g. one built over a shared <see cref="HttpClient"/>). Text over
    /// the service's 5,120-character document limit is analyzed in overlapping windows.
    /// </summary>
    /// <param name="builder">The policy builder.</param>
    /// <param name="client">The Azure PII client to delegate to.</param>
    /// <param name="azureOptions">Azure PII detector configuration (supported entities, timeout, fail-open, category map).</param>
    /// <param name="piiOptions">Optional PII detection/anonymization configuration.</param>
    /// <returns>The builder for chaining.</returns>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <see cref="AzurePiiOptions.ConfidenceThreshold"/> is NaN or outside 0.0-1.0.</exception>
    public static GuardrailPolicyBuilder RedactPiiWithAzure(
        this GuardrailPolicyBuilder builder,
        AzurePiiClient client,
        AzurePiiOptions azureOptions,
        PiiOptions? piiOptions = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(azureOptions);
        ValidateConfidenceThreshold(azureOptions);

        // resolve the analysis language the same way PiiRule will (piiOptions?.Language ?? "en") and pin
        // the recognizer to it, so the registry never filters the Azure recognizer out on a mismatch.
        var language = piiOptions?.Language ?? "en";
        var registry = PiiRecognizers.CreateRegistry(language, piiOptions?.Countries);

        // the recognizer wraps the Azure client, which owns an HttpClient. TasmanianDevil 0.2.1
        // does not make either disposable; 0.3.0 does, so the handover is written to pick up
        // whichever of them implements IDisposable at runtime.
        var recognizer = new AzurePiiRecognizer(client, azureOptions, supportedLanguage: language);

        // the recognizer sends the whole text as one document, so text over the service's document
        // limit is split into windows that fit. The wrapper does not take over the recognizer's
        // lifetime; the rule still owns the recognizer and the client below.
        registry.AddRecognizer(new ChunkingEntityRecognizer(recognizer, MaxChunkLength, ChunkOverlap));
        var owned = Disposables(recognizer, client);

        // defaultScoreThreshold 0 here; PiiRule applies PiiOptions.ScoreThreshold per evaluation.
        var engine = new AnalyzerEngine(
            registry,
            new LemmaContextAwareEnhancer(contextMatchingMode: piiOptions?.ContextMatchingMode ?? ContextMatchingMode.Substring),
            defaultScoreThreshold: 0);

        builder.AddRule(new PiiRule(piiOptions, analyzer: engine, ownedResources: owned));
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

    // a threshold above 1.0 would drop every entity the service returns, and a NaN one would filter
    // nothing, both without a word
    private static void ValidateConfidenceThreshold(AzurePiiOptions azureOptions)
    {
        if (azureOptions.ConfidenceThreshold is { } threshold && threshold is not (>= 0d and <= 1d))
        {
            throw new ArgumentOutOfRangeException(
                nameof(azureOptions), threshold, "ConfidenceThreshold must be between 0.0 and 1.0.");
        }
    }

    /// <summary>
    /// Collects whichever of the supplied objects implement <see cref="IDisposable"/>, so the
    /// handover survives the engine package gaining (or losing) disposability between versions.
    /// </summary>
    private static List<IDisposable> Disposables(params object[] candidates)
    {
        var owned = new List<IDisposable>(candidates.Length);
        foreach (var candidate in candidates)
        {
            if (candidate is IDisposable disposable && !owned.Contains(disposable))
                owned.Add(disposable);
        }

        return owned;
    }
}
