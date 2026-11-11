using System.Reflection;
using AgentGuard.Core.Abstractions;
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
    /// <para>
    /// A failed remote call (unreachable endpoint, failure status, timeout) is never a clean result.
    /// With <see cref="RemotePiiOptions.FailOpen"/> on (the default) the text continues with what the
    /// local recognizers found redacted, and the rule's result has
    /// <see cref="GuardrailResult.IsError"/> set, so the pipeline logs and records that the remote
    /// entities were not checked. With it off the rule blocks the text with an error result.
    /// </para>
    /// </summary>
    /// <param name="builder">The policy builder.</param>
    /// <param name="remoteOptions">Remote detector configuration (endpoint, auth, supported entities, timeout, fail-open).</param>
    /// <param name="piiOptions">Optional PII detection/anonymization configuration (entities, countries, operators).</param>
    /// <returns>The builder for chaining.</returns>
    /// <exception cref="ArgumentException">
    /// <see cref="RemotePiiOptions.SupportedEntities"/> is empty or names something that is neither an
    /// entity type of the engine (the <see cref="PiiEntities"/> constants, matched ignoring case) nor
    /// named in <see cref="RemotePiiOptions.CategoryMap"/>. The message lists the accepted names.
    /// </exception>
    public static GuardrailPolicyBuilder RedactPiiWithRemote(
        this GuardrailPolicyBuilder builder,
        RemotePiiOptions remoteOptions,
        PiiOptions? piiOptions = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(remoteOptions);

        // the options are checked before a client, and the HttpClient it owns, exists to be leaked
        var prepared = Prepare(remoteOptions);
        return AddRule(builder, new HttpPiiDetectionClient(prepared), prepared, piiOptions);
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
    /// <exception cref="ArgumentException"><see cref="RemotePiiOptions.SupportedEntities"/> is empty or holds an unknown entity type.</exception>
    public static GuardrailPolicyBuilder RedactPiiWithRemote(
        this GuardrailPolicyBuilder builder,
        HttpClient httpClient,
        RemotePiiOptions remoteOptions,
        PiiOptions? piiOptions = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(httpClient);
        ArgumentNullException.ThrowIfNull(remoteOptions);

        var prepared = Prepare(remoteOptions);
        return AddRule(builder, new HttpPiiDetectionClient(httpClient, prepared), prepared, piiOptions);
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
    /// <exception cref="ArgumentException"><see cref="RemotePiiOptions.SupportedEntities"/> is empty or holds an unknown entity type.</exception>
    public static GuardrailPolicyBuilder RedactPiiWithRemote(
        this GuardrailPolicyBuilder builder,
        IPiiDetectionClient client,
        RemotePiiOptions remoteOptions,
        PiiOptions? piiOptions = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(remoteOptions);

        return AddRule(builder, client, Prepare(remoteOptions), piiOptions);
    }

    private static GuardrailPolicyBuilder AddRule(
        GuardrailPolicyBuilder builder, IPiiDetectionClient client, RemotePiiOptions remoteOptions, PiiOptions? piiOptions)
    {
        // resolve the analysis language the same way PiiRule will (piiOptions?.Language ?? "en") and pin
        // the recognizer to it, so the registry never filters the remote recognizer out on a mismatch.
        var language = piiOptions?.Language ?? "en";
        var registry = PiiRecognizers.CreateRegistry(language, piiOptions?.Countries);

        // the recognizer wraps the detection client, which for the built-in HTTP one owns an
        // HttpClient. TasmanianDevil 0.2.1 does not make either disposable; 0.3.0 does, so the
        // handover is written to pick up whichever of them implements IDisposable at runtime.
        var recognizer = new RemotePiiRecognizer(client, remoteOptions, supportedLanguage: language);
        registry.AddRecognizer(recognizer);
        var owned = Disposables(recognizer, client);

        // defaultScoreThreshold 0 here; PiiRule applies PiiOptions.ScoreThreshold per evaluation.
        var engine = new AnalyzerEngine(
            registry,
            new LemmaContextAwareEnhancer(contextMatchingMode: piiOptions?.ContextMatchingMode ?? ContextMatchingMode.Substring),
            defaultScoreThreshold: 0);

        // the recognizer reports a remote failure it swallows (see Prepare) and throws one it does
        // not; either way the rule turns it into an error result of the matching kind
        var ruleOptions = new PiiRuleOptions
        {
            OnError = remoteOptions.FailOpen ? ErrorBehavior.FailOpen : ErrorBehavior.FailClosed,
        };

        builder.AddRule(new PiiRule(piiOptions, analyzer: engine, ownedResources: owned, ruleOptions: ruleOptions));
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
    /// <summary>
    /// The options the recognizer runs with: the caller's, with the supported entity names checked
    /// and put in their canonical spelling, and with a failure the recognizer swallows reported to
    /// the rule before the caller's own <see cref="RemotePiiOptions.OnError"/> sees it.
    /// </summary>
    private static RemotePiiOptions Prepare(RemotePiiOptions remoteOptions)
    {
        if (remoteOptions.SupportedEntities is not { Count: > 0 })
        {
            throw new ArgumentException(
                "SupportedEntities must name at least one entity type the remote detector finds.", nameof(remoteOptions));
        }

        // an entity type of the detector's own is known once the category map names it
        var categoryMap = remoteOptions.CategoryMap;
        var entities = PiiEntityNames.Resolve(
            remoteOptions.SupportedEntities,
            PiiEntityNames.Canonical.Concat(categoryMap?.Values ?? []),
            categoryMap,
            nameof(remoteOptions));

        var callback = remoteOptions.OnError;
        Action<Exception> onError = exception =>
        {
            PiiRule.ReportRecognizerFailure("Remote PII detector", exception);
            callback?.Invoke(exception);
        };

        // copied property by property rather than through an initializer, so a setting a newer
        // version of the options type adds is carried over instead of reset to its default
        var prepared = Activator.CreateInstance<RemotePiiOptions>();
        foreach (var property in typeof(RemotePiiOptions).GetProperties(BindingFlags.Public | BindingFlags.Instance))
        {
            if (property is not { CanRead: true, SetMethod.IsPublic: true })
                continue;

            property.SetValue(prepared, property.Name switch
            {
                nameof(RemotePiiOptions.SupportedEntities) => entities,
                nameof(RemotePiiOptions.OnError) => onError,
                _ => property.GetValue(remoteOptions),
            });
        }

        return prepared;
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
