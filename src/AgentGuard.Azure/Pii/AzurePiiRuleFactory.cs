using System.Globalization;
using AgentGuard.Core.Builders;
using AgentGuard.Core.Configuration;
using Azure.Core;
using Azure.Identity;
using TasmanianDevil;
using TasmanianDevil.Azure;

namespace AgentGuard.Azure.Pii;

/// <summary>
/// Makes the <c>AzurePii</c> rule type configurable from <c>appsettings.json</c>.
/// </summary>
/// <remarks>
/// <para>
/// Register it alongside <c>AddAgentGuard</c>:
/// <code>
/// services.AddSingleton&lt;IGuardrailRuleFactory, AzurePiiRuleFactory&gt;();
/// </code>
/// It lives here rather than in <c>AgentGuard.Hosting</c> so that taking the hosting package does
/// not drag <c>Azure.Identity</c>, the Content Safety SDK and <c>TasmanianDevil.Azure</c> into
/// applications that never talk to Azure. This is also the only place a
/// <see cref="TokenCredential"/> is bound to the engine's dependency-free token-provider delegate.
/// </para>
/// <para>
/// Binds <see cref="RuleConfiguration.Endpoint"/> and <see cref="RuleConfiguration.Entities"/>
/// (required; the entity types to detect), <see cref="RuleConfiguration.SubscriptionKey"/> or
/// <see cref="RuleConfiguration.UseManagedIdentity"/>, <see cref="RuleConfiguration.Domain"/>,
/// <see cref="RuleConfiguration.TimeoutSeconds"/> and <see cref="RuleConfiguration.FailOpen"/>, plus
/// the PII settings <c>PiiRedaction</c> honours: <see cref="RuleConfiguration.Replacement"/> and
/// <see cref="RuleConfiguration.Countries"/>.
/// </para>
/// </remarks>
public sealed class AzurePiiRuleFactory : IGuardrailRuleFactory
{
    private const string CognitiveServicesScope = "https://cognitiveservices.azure.com/.default";

    /// <inheritdoc />
    public string RuleType => "AzurePii";

    /// <inheritdoc />
    public void Configure(GuardrailPolicyBuilder builder, RuleConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configuration);

        var endpoint = configuration.Endpoint
            ?? throw new InvalidOperationException("AzurePii requires Endpoint.");

        var entities = configuration.Entities is { Count: > 0 }
            ? configuration.Entities
            : throw new InvalidOperationException("AzurePii requires Entities (the entity types to detect).");

        var useManagedIdentity = configuration.UseManagedIdentity ?? false;

        if (!useManagedIdentity && string.IsNullOrEmpty(configuration.SubscriptionKey))
            throw new InvalidOperationException("AzurePii requires SubscriptionKey, or UseManagedIdentity: true.");

        if (configuration.TimeoutSeconds is < 1)
        {
            throw new InvalidOperationException(string.Create(CultureInfo.InvariantCulture,
                $"AzurePii: TimeoutSeconds must be at least 1, but was {configuration.TimeoutSeconds}."));
        }

        builder.RedactPiiWithAzure(
            new AzurePiiOptions
            {
                Endpoint = endpoint,
                SupportedEntities = entities,
                Domain = ParseDomain(configuration.Domain),
                Timeout = TimeSpan.FromSeconds(configuration.TimeoutSeconds ?? 10),
                FailOpen = configuration.FailOpen ?? true,
                SubscriptionKey = useManagedIdentity ? null : configuration.SubscriptionKey,
                TokenProvider = useManagedIdentity ? CreateManagedIdentityTokenProvider() : null,
            },
            // Entities above is what Azure is asked to detect, not a filter on what is redacted: the
            // local recognizers keep detecting everything, as with the code-based overloads
            new PiiOptions
            {
                Replacement = configuration.Replacement,
                Countries = configuration.Countries is { Count: > 0 } ? configuration.Countries : null,
            });
    }

    private static AzurePiiDomain ParseDomain(string? value)
    {
        if (string.IsNullOrEmpty(value))
            return AzurePiiDomain.None;

        // only member names, compared ordinally; Enum.TryParse alone would also take any number
        var names = Enum.GetNames<AzurePiiDomain>();
        if (names.Contains(value.Trim(), StringComparer.OrdinalIgnoreCase)
            && Enum.TryParse<AzurePiiDomain>(value, ignoreCase: true, out var parsed))
        {
            return parsed;
        }

        throw new InvalidOperationException(
            $"'{value}' is not a valid Domain. Valid values: {string.Join(", ", names)}.");
    }

    private static Func<CancellationToken, ValueTask<string>> CreateManagedIdentityTokenProvider()
    {
        var credential = new DefaultAzureCredential();
        var scope = new TokenRequestContext([CognitiveServicesScope]);
        return async ct =>
        {
            var token = await credential.GetTokenAsync(scope, ct).ConfigureAwait(false);
            return token.Token;
        };
    }
}
