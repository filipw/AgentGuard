using AgentGuard.Core.Builders;
using AgentGuard.Core.Configuration;
using Azure.Core;
using Azure.Identity;
using TasmanianDevil.Azure;

namespace AgentGuard.Azure.Pii;

/// <summary>
/// Makes the <c>AzurePii</c> rule type configurable from <c>appsettings.json</c>.
/// </summary>
/// <remarks>
/// Register it alongside <c>AddAgentGuard</c>:
/// <code>
/// services.AddSingleton&lt;IGuardrailRuleFactory, AzurePiiRuleFactory&gt;();
/// </code>
/// It lives here rather than in <c>AgentGuard.Hosting</c> so that taking the hosting package does
/// not drag <c>Azure.Identity</c>, the Content Safety SDK and <c>TasmanianDevil.Azure</c> into
/// applications that never talk to Azure. This is also the only place a
/// <see cref="TokenCredential"/> is bound to the engine's dependency-free token-provider delegate.
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

        builder.RedactPiiWithAzure(new AzurePiiOptions
        {
            Endpoint = endpoint,
            SupportedEntities = entities,
            Domain = ParseDomain(configuration.Domain),
            Timeout = TimeSpan.FromSeconds(configuration.TimeoutSeconds ?? 10),
            FailOpen = configuration.FailOpen ?? true,
            SubscriptionKey = useManagedIdentity ? null : configuration.SubscriptionKey,
            TokenProvider = useManagedIdentity ? CreateManagedIdentityTokenProvider() : null,
        });
    }

    private static AzurePiiDomain ParseDomain(string? value)
    {
        if (string.IsNullOrEmpty(value))
            return AzurePiiDomain.None;

        return Enum.TryParse<AzurePiiDomain>(value, ignoreCase: true, out var parsed)
            ? parsed
            : throw new InvalidOperationException(
                $"'{value}' is not a valid Domain. Valid values: {string.Join(", ", Enum.GetNames<AzurePiiDomain>())}.");
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
