using AgentGuard.Core.Builders;
using AgentGuard.Core.Configuration;
using TasmanianDevil.Remote;

namespace AgentGuard.RemotePii;

/// <summary>
/// Makes the <c>RemotePii</c> rule type configurable from <c>appsettings.json</c>.
/// </summary>
/// <remarks>
/// Register it alongside <c>AddAgentGuard</c>:
/// <code>
/// services.AddSingleton&lt;IGuardrailRuleFactory, RemotePiiRuleFactory&gt;();
/// </code>
/// It lives here rather than in <c>AgentGuard.Hosting</c> so that taking the hosting package does
/// not drag the out-of-process detector, and its transitive dependencies, into applications that
/// never configure one.
/// </remarks>
public sealed class RemotePiiRuleFactory : IGuardrailRuleFactory
{
    /// <inheritdoc />
    public string RuleType => "RemotePii";

    /// <inheritdoc />
    public void Configure(GuardrailPolicyBuilder builder, RuleConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configuration);

        var endpoint = configuration.Endpoint
            ?? throw new InvalidOperationException("RemotePii requires Endpoint.");

        var entities = configuration.Entities is { Count: > 0 }
            ? configuration.Entities
            : throw new InvalidOperationException(
                "RemotePii requires Entities (the entity types the remote endpoint detects).");

        builder.RedactPiiWithRemote(new RemotePiiOptions
        {
            Endpoint = endpoint,
            SupportedEntities = entities,
            AuthHeaderName = configuration.AuthHeaderName,
            AuthHeaderValue = configuration.AuthHeaderValue,
            Timeout = TimeSpan.FromSeconds(configuration.TimeoutSeconds ?? 10),
            FailOpen = configuration.FailOpen ?? true,
        });
    }
}
