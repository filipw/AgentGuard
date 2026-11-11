using System.Reflection;
using AgentGuard.Core.Abstractions;
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
    /// <para>
    /// A failed Azure call (unreachable resource, failure status, timeout, a per-document error) is
    /// never a clean result, and neither is a long text of which only some windows could be analyzed.
    /// With <see cref="AzurePiiOptions.FailOpen"/> on (the default) the text continues with what was
    /// found - by the local recognizers and in the windows that were analyzed - redacted, and the
    /// rule's result has <see cref="GuardrailResult.IsError"/> set, so the pipeline logs and records
    /// that the detection was incomplete. With it off the rule blocks the text with an error result.
    /// </para>
    /// <para>
    /// <see cref="AzurePiiOptions.SupportedEntities"/> takes the engine's entity types
    /// (<c>PERSON</c>, <c>EMAIL_ADDRESS</c>) and, ignoring case, the Azure category names the category
    /// map translates to them (<c>Person</c>, <c>Email</c>). An Azure category the map does not cover
    /// is accepted under its own name once <see cref="AzurePiiOptions.PiiCategories"/> requests it.
    /// </para>
    /// </summary>
    /// <param name="builder">The policy builder.</param>
    /// <param name="azureOptions">Azure PII detector configuration (endpoint, auth, supported entities, domain, timeout, fail-open).</param>
    /// <param name="piiOptions">Optional PII detection/anonymization configuration (entities, countries, operators).</param>
    /// <returns>The builder for chaining.</returns>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <see cref="AzurePiiOptions.ConfidenceThreshold"/> is NaN or outside 0.0-1.0.</exception>
    /// <exception cref="ArgumentException">
    /// <see cref="AzurePiiOptions.SupportedEntities"/> is empty or names something the Azure detector
    /// cannot return under the category map in use. The message lists the accepted names.
    /// </exception>
    public static GuardrailPolicyBuilder RedactPiiWithAzure(
        this GuardrailPolicyBuilder builder,
        AzurePiiOptions azureOptions,
        PiiOptions? piiOptions = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(azureOptions);

        // the options are checked before a client, and the HttpClient it owns, exists to be leaked
        var prepared = Prepare(azureOptions);
        return AddRule(builder, new AzurePiiClient(prepared), prepared, piiOptions);
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
    /// <exception cref="ArgumentException"><see cref="AzurePiiOptions.SupportedEntities"/> is empty or holds a name the Azure detector cannot return.</exception>
    public static GuardrailPolicyBuilder RedactPiiWithAzure(
        this GuardrailPolicyBuilder builder,
        AzurePiiClient client,
        AzurePiiOptions azureOptions,
        PiiOptions? piiOptions = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(azureOptions);

        return AddRule(builder, client, Prepare(azureOptions), piiOptions);
    }

    private static GuardrailPolicyBuilder AddRule(
        GuardrailPolicyBuilder builder, AzurePiiClient client, AzurePiiOptions azureOptions, PiiOptions? piiOptions)
    {
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

        // the recognizer reports an Azure failure it swallows (see Prepare) and throws one it does
        // not; either way the rule turns it into an error result of the matching kind
        var ruleOptions = new PiiRuleOptions
        {
            OnError = azureOptions.FailOpen ? ErrorBehavior.FailOpen : ErrorBehavior.FailClosed,
        };

        builder.AddRule(new PiiRule(piiOptions, analyzer: engine, ownedResources: owned, ruleOptions: ruleOptions));
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

    /// <summary>
    /// The options the recognizer runs with: the caller's, with the supported entity names checked
    /// and put in the engine's spelling, and with a failure the recognizer swallows reported to the
    /// rule before the caller's own <see cref="AzurePiiOptions.OnError"/> sees it.
    /// </summary>
    private static AzurePiiOptions Prepare(AzurePiiOptions azureOptions)
    {
        ValidateConfidenceThreshold(azureOptions);

        if (azureOptions.SupportedEntities is not { Count: > 0 })
        {
            throw new ArgumentException(
                "SupportedEntities must name at least one entity type for Azure to detect.", nameof(azureOptions));
        }

        // what the recognizer can hand back: the entity types the category map translates to, and
        // a requested category the map leaves alone, which comes back under its own name
        var categoryMap = azureOptions.CategoryMap ?? AzurePiiCategoryMap.Default;
        var unmappedCategories = (azureOptions.PiiCategories ?? [])
            .Where(category => !categoryMap.Keys.Contains(category, StringComparer.OrdinalIgnoreCase));

        var entities = PiiEntityNames.Resolve(
            azureOptions.SupportedEntities,
            categoryMap.Values.Concat(unmappedCategories),
            categoryMap,
            nameof(azureOptions));

        var callback = azureOptions.OnError;
        Action<Exception> onError = exception =>
        {
            PiiRule.ReportRecognizerFailure("Azure AI Language PII detection", exception);
            callback?.Invoke(exception);
        };

        // copied property by property rather than through an initializer, so a setting a newer
        // version of the options type adds is carried over instead of reset to its default
        var prepared = Activator.CreateInstance<AzurePiiOptions>();
        foreach (var property in typeof(AzurePiiOptions).GetProperties(BindingFlags.Public | BindingFlags.Instance))
        {
            if (property is not { CanRead: true, SetMethod.IsPublic: true })
                continue;

            property.SetValue(prepared, property.Name switch
            {
                nameof(AzurePiiOptions.SupportedEntities) => entities,
                nameof(AzurePiiOptions.OnError) => onError,
                _ => property.GetValue(azureOptions),
            });
        }

        return prepared;
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
