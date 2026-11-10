using AgentGuard.Core.Configuration;
using Microsoft.Extensions.Configuration;

namespace AgentGuard.Hosting.Configuration;

/// <summary>
/// Reads <see cref="AgentGuardConfiguration"/> from <see cref="IConfiguration"/>, failing on anything it
/// can't read rather than leaving it out.
/// </summary>
/// <remarks>
/// The configuration binder skips an element of a collection it fails to bind - a rule with an
/// unparseable value would simply be missing from the policy, and a policy that was meant to fail closed
/// would lose the rule instead. So keys the model doesn't have are an error, and every rule section is
/// checked to have been read; one that wasn't is bound again on its own, which reports the setting
/// that failed.
/// </remarks>
internal static class AgentGuardConfigurationReader
{
    private static readonly Action<BinderOptions> Strict = options => options.ErrorOnUnknownConfiguration = true;

    /// <summary>Reads the configuration.</summary>
    /// <exception cref="InvalidOperationException">A setting can't be read, or a key is not a known setting.</exception>
    public static AgentGuardConfiguration Read(IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        AgentGuardConfiguration config;
        try
        {
            config = configuration.Get<AgentGuardConfiguration>(Strict) ?? new AgentGuardConfiguration();
        }
        catch (InvalidOperationException ex)
        {
            // the binder's own message names neither the policy nor the rule; find the rule that fails
            foreach (var (section, name) in PolicySections(configuration))
                ThrowIfARuleCannotBeRead(section, name);

            throw new InvalidOperationException($"AgentGuard configuration could not be read: {Describe(ex)}", ex);
        }

        // matched by where each section sits under the configuration that was passed in, not by its
        // absolute path: the usual argument is a section such as GetSection("AgentGuard")
        VerifyRules(DefaultPolicySection(configuration), config.DefaultPolicy, DefaultPolicyName);

        foreach (var policySection in NamedPolicySections(configuration))
            VerifyRules(policySection, config.Policies.GetValueOrDefault(policySection.Key), NamedPolicy(policySection));

        return config;
    }

    private const string DefaultPolicyName = "default policy";

    private static IConfigurationSection DefaultPolicySection(IConfiguration configuration) =>
        configuration.GetSection(nameof(AgentGuardConfiguration.DefaultPolicy));

    private static IEnumerable<IConfigurationSection> NamedPolicySections(IConfiguration configuration) =>
        configuration.GetSection(nameof(AgentGuardConfiguration.Policies)).GetChildren();

    private static string NamedPolicy(IConfigurationSection policySection) => $"policy '{policySection.Key}'";

    private static IEnumerable<(IConfigurationSection Section, string Name)> PolicySections(IConfiguration configuration)
    {
        yield return (DefaultPolicySection(configuration), DefaultPolicyName);

        foreach (var policySection in NamedPolicySections(configuration))
            yield return (policySection, NamedPolicy(policySection));
    }

    private static void VerifyRules(IConfigurationSection policySection, PolicyConfiguration? policy, string policyName)
    {
        var ruleCount = policySection.GetSection(nameof(PolicyConfiguration.Rules)).GetChildren().Count();
        if (ruleCount == 0 || (policy?.Rules.Count ?? 0) == ruleCount)
            return;

        // the binder dropped at least one rule: bind each on its own, so the one that fails says why
        ThrowIfARuleCannotBeRead(policySection, policyName);

        throw new InvalidOperationException(
            $"AgentGuard {policyName}: {ruleCount} rules are configured but only {policy?.Rules.Count ?? 0} could be read.");
    }

    private static void ThrowIfARuleCannotBeRead(IConfigurationSection policySection, string policyName)
    {
        foreach (var ruleSection in policySection.GetSection(nameof(PolicyConfiguration.Rules)).GetChildren())
        {
            try
            {
                ruleSection.Get<RuleConfiguration>(Strict);
            }
            catch (InvalidOperationException ex)
            {
                var type = ruleSection[nameof(RuleConfiguration.Type)] ?? "(no type)";
                throw new InvalidOperationException(
                    $"AgentGuard {policyName}: rule {ruleSection.Key} ('{type}') could not be read from configuration: {Describe(ex)}", ex);
            }
        }
    }

    // the binder wraps the failure that names the setting (an unparseable value, an unknown key) in
    // a generic one, so report the whole chain
    private static string Describe(Exception ex)
    {
        var messages = new List<string>();
        for (var current = ex; current is not null; current = current.InnerException)
        {
            if (!messages.Contains(current.Message))
                messages.Add(current.Message);
        }

        return string.Join(" ", messages);
    }
}
