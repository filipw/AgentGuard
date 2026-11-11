using System.Globalization;
using AgentGuard.Core.Builders;
using AgentGuard.Core.Configuration;
using TasmanianDevil;
using TasmanianDevil.Remote;

namespace AgentGuard.RemotePii;

/// <summary>
/// Makes the <c>RemotePii</c> rule type configurable from <c>appsettings.json</c>.
/// </summary>
/// <remarks>
/// <para>
/// Register it alongside <c>AddAgentGuard</c>:
/// <code>
/// services.AddSingleton&lt;IGuardrailRuleFactory, RemotePiiRuleFactory&gt;();
/// </code>
/// It lives here rather than in <c>AgentGuard.Hosting</c> so that taking the hosting package does
/// not drag the out-of-process detector, and its transitive dependencies, into applications that
/// never configure one.
/// </para>
/// <para>
/// Binds <see cref="RuleConfiguration.Endpoint"/> and <see cref="RuleConfiguration.Entities"/>
/// (required; the entity types the remote endpoint detects), <see cref="RuleConfiguration.AuthHeaderName"/>,
/// <see cref="RuleConfiguration.AuthHeaderValue"/>, <see cref="RuleConfiguration.TimeoutSeconds"/> and
/// <see cref="RuleConfiguration.FailOpen"/>, plus the PII settings <c>PiiRedaction</c> honours:
/// <see cref="RuleConfiguration.Replacement"/> and <see cref="RuleConfiguration.Countries"/>.
/// Any other setting on the rule entry, and an entity name that is not a known entity type, is a
/// configuration error.
/// </para>
/// <para>
/// With <c>FailOpen</c> left on, a failed remote call lets the text through with the local redactions
/// applied and an error result (<c>IsError</c>) that the pipeline logs and records; with
/// <c>"FailOpen": false</c> it blocks the text.
/// </para>
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

        RuleSettings.EnsureOnly(
            configuration,
            nameof(RuleConfiguration.Endpoint),
            nameof(RuleConfiguration.Entities),
            nameof(RuleConfiguration.AuthHeaderName),
            nameof(RuleConfiguration.AuthHeaderValue),
            nameof(RuleConfiguration.TimeoutSeconds),
            nameof(RuleConfiguration.FailOpen),
            nameof(RuleConfiguration.Replacement),
            nameof(RuleConfiguration.Countries));

        var endpoint = configuration.Endpoint
            ?? throw new InvalidOperationException("RemotePii requires Endpoint.");

        var entities = configuration.Entities is { Count: > 0 }
            ? configuration.Entities
            : throw new InvalidOperationException(
                "RemotePii requires Entities (the entity types the remote endpoint detects).");

        if (configuration.TimeoutSeconds is < 1)
        {
            throw new InvalidOperationException(string.Create(CultureInfo.InvariantCulture,
                $"RemotePii: TimeoutSeconds must be at least 1, but was {configuration.TimeoutSeconds}."));
        }

        try
        {
            builder.RedactPiiWithRemote(
                new RemotePiiOptions
                {
                    Endpoint = endpoint,
                    SupportedEntities = entities,
                    AuthHeaderName = configuration.AuthHeaderName,
                    AuthHeaderValue = configuration.AuthHeaderValue,
                    Timeout = TimeSpan.FromSeconds(configuration.TimeoutSeconds ?? 10),
                    FailOpen = configuration.FailOpen ?? true,
                },
                // Entities above is what the remote detector supports, not a filter on what is redacted:
                // the local recognizers keep detecting everything, as with the code-based overloads
                new PiiOptions
                {
                    Replacement = configuration.Replacement,
                    Countries = configuration.Countries is { Count: > 0 } ? configuration.Countries : null,
                });
        }
        catch (ArgumentException ex)
        {
            // a setting the builder rejects is a configuration error like the ones above
            var message = ex.ParamName is null
                ? ex.Message
                : ex.Message.Replace($" (Parameter '{ex.ParamName}')", "", StringComparison.Ordinal);
            throw new InvalidOperationException($"RemotePii: {message}", ex);
        }
    }
}
