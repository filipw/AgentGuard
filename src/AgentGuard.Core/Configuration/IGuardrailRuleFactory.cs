using AgentGuard.Core.Builders;

namespace AgentGuard.Core.Configuration;

/// <summary>
/// Builds one configured rule type, so a rule can be reachable from <c>appsettings.json</c> without
/// <c>AgentGuard.Hosting</c> having to reference the package it lives in.
/// </summary>
/// <remarks>
/// <para>
/// The configuration mapper handles the rule types that live in the core engine directly and hands
/// anything else to the registered factories, matching on <see cref="RuleType"/>. That is what keeps
/// the cloud and out-of-process adapters - and their transitive dependencies, such as the Azure SDK -
/// out of every application that merely wants DI registration.
/// </para>
/// <para>
/// Register one per rule type alongside <c>AddAgentGuard</c>:
/// <code>
/// services.AddSingleton&lt;IGuardrailRuleFactory, AzurePiiRuleFactory&gt;();
/// services.AddAgentGuard(builder.Configuration.GetSection("AgentGuard"));
/// </code>
/// </para>
/// </remarks>
public interface IGuardrailRuleFactory
{
    /// <summary>
    /// The <see cref="RuleConfiguration.Type"/> value this factory claims, compared
    /// case-insensitively (for example <c>AzurePii</c>).
    /// </summary>
    string RuleType { get; }

    /// <summary>Adds the configured rule to the policy being built.</summary>
    /// <param name="builder">The policy under construction.</param>
    /// <param name="configuration">The bound settings for this rule entry.</param>
    /// <exception cref="InvalidOperationException">A required setting is missing or invalid.</exception>
    void Configure(GuardrailPolicyBuilder builder, RuleConfiguration configuration);
}
