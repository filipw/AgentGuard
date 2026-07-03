using AgentGuard.Core.Builders;
using AgentGuard.Pii;
using TasmanianDevil;
using TasmanianDevil.Analyzer;
using TasmanianDevil.Analyzer.Context;
using TasmanianDevil.Remote;

namespace AgentGuard.RemotePii;

/// <summary>
/// Extension methods for adding out-of-process PII detection to the policy builder.
/// </summary>
public static class RemotePiiGuardrailBuilderExtensions
{
    /// <summary>
    /// Adds PII redaction (order 20) augmented with an out-of-process detector reached over a
    /// generic HTTP contract - an escape hatch for entities that need a model too heavy to load
    /// in-process (e.g. name/address detection in a container that can't fit the ~580 MB GLiNER
    /// model). The remote service is a detector only: it returns entity spans, which flow through
    /// the same local <c>AnonymizerEngine</c> as the regex/checksum entities, so anonymization,
    /// reversible encrypt/decrypt, and conflict resolution keep working unchanged.
    /// <para>
    /// PRIVACY: this sends the raw, unredacted analyzed text to <see cref="RemotePiiOptions.Endpoint"/>.
    /// That is the inherent tradeoff of out-of-process detection - see docs/remote-pii.md.
    /// </para>
    /// </summary>
    /// <param name="builder">The policy builder.</param>
    /// <param name="remoteOptions">Remote detector configuration (endpoint, auth, supported entities, timeout, fail-open).</param>
    /// <param name="piiOptions">Optional PII detection/anonymization configuration (entities, countries, operators).</param>
    /// <returns>The builder for chaining.</returns>
    public static GuardrailPolicyBuilder RedactPiiWithRemote(
        this GuardrailPolicyBuilder builder,
        RemotePiiOptions remoteOptions,
        PiiOptions? piiOptions = null)
    {
        ArgumentNullException.ThrowIfNull(remoteOptions);
        return builder.RedactPiiWithRemote(new HttpPiiDetectionClient(remoteOptions), remoteOptions, piiOptions);
    }

    /// <summary>
    /// Adds PII redaction (order 20) augmented with an out-of-process detector, using an existing
    /// <see cref="HttpClient"/> (e.g. from <c>IHttpClientFactory</c>) so retries, timeouts, and other
    /// HTTP pipeline behavior are configured through the standard .NET mechanisms.
    /// </summary>
    /// <param name="builder">The policy builder.</param>
    /// <param name="httpClient">Pre-configured HttpClient instance.</param>
    /// <param name="remoteOptions">Remote detector configuration.</param>
    /// <param name="piiOptions">Optional PII detection/anonymization configuration.</param>
    /// <returns>The builder for chaining.</returns>
    public static GuardrailPolicyBuilder RedactPiiWithRemote(
        this GuardrailPolicyBuilder builder,
        HttpClient httpClient,
        RemotePiiOptions remoteOptions,
        PiiOptions? piiOptions = null)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        ArgumentNullException.ThrowIfNull(remoteOptions);
        return builder.RedactPiiWithRemote(new HttpPiiDetectionClient(httpClient, remoteOptions), remoteOptions, piiOptions);
    }

    /// <summary>
    /// Adds PII redaction (order 20) augmented with a custom <see cref="IPiiDetectionClient"/> -
    /// the full escape hatch for a transport other than the built-in <see cref="HttpPiiDetectionClient"/>.
    /// </summary>
    /// <param name="builder">The policy builder.</param>
    /// <param name="client">The remote detection client to delegate to.</param>
    /// <param name="remoteOptions">Remote detector configuration (supported entities, timeout, fail-open, category map).</param>
    /// <param name="piiOptions">Optional PII detection/anonymization configuration.</param>
    /// <returns>The builder for chaining.</returns>
    public static GuardrailPolicyBuilder RedactPiiWithRemote(
        this GuardrailPolicyBuilder builder,
        IPiiDetectionClient client,
        RemotePiiOptions remoteOptions,
        PiiOptions? piiOptions = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(remoteOptions);

        // resolve the analysis language the same way PiiRule will (piiOptions?.Language ?? "en") and pin
        // the recognizer to it, so the registry never filters the remote recognizer out on a mismatch.
        var language = piiOptions?.Language ?? "en";
        var registry = PiiRecognizers.CreateRegistry(language, piiOptions?.Countries);
        registry.AddRecognizer(new RemotePiiRecognizer(client, remoteOptions, supportedLanguage: language));

        // defaultScoreThreshold 0 here; PiiRule applies PiiOptions.ScoreThreshold per evaluation.
        var engine = new AnalyzerEngine(
            registry,
            new LemmaContextAwareEnhancer(contextMatchingMode: piiOptions?.ContextMatchingMode ?? ContextMatchingMode.Substring),
            defaultScoreThreshold: 0);

        builder.AddRule(new PiiRule(piiOptions, analyzer: engine));
        return builder;
    }

    /// <summary>
    /// Adds PII redaction (order 20) augmented with an out-of-process detector at
    /// <paramref name="endpoint"/>, detecting the given <paramref name="entities"/>. Shorthand for
    /// the common case; use the <see cref="RemotePiiOptions"/> overload for auth headers, a custom
    /// timeout, fail-closed behavior, or a category map.
    /// </summary>
    /// <param name="builder">The policy builder.</param>
    /// <param name="endpoint">Base URL of the remote detection endpoint.</param>
    /// <param name="entities">The entity types the remote endpoint detects (e.g. <c>[PiiEntities.Person, PiiEntities.Address]</c>).</param>
    /// <param name="piiOptions">Optional PII detection/anonymization configuration.</param>
    /// <returns>The builder for chaining.</returns>
    public static GuardrailPolicyBuilder RedactPiiWithRemote(
        this GuardrailPolicyBuilder builder,
        string endpoint,
        IReadOnlyList<string> entities,
        PiiOptions? piiOptions = null)
    {
        return builder.RedactPiiWithRemote(
            new RemotePiiOptions { Endpoint = endpoint, SupportedEntities = entities },
            piiOptions);
    }
}
