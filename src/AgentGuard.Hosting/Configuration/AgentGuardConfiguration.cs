using AgentGuard.Core.Configuration;

namespace AgentGuard.Hosting.Configuration;

/// <summary>
/// Root configuration for AgentGuard policies, bound from appsettings.json.
/// </summary>
public sealed class AgentGuardConfiguration
{
    /// <summary>
    /// Configuration for the default policy.
    /// </summary>
    public PolicyConfiguration? DefaultPolicy { get; set; }

    /// <summary>
    /// Named policies, keyed by policy name.
    /// </summary>
    public Dictionary<string, PolicyConfiguration> Policies { get; set; } = [];
}

/// <summary>
/// Configuration for a single guardrail policy.
/// </summary>
public sealed class PolicyConfiguration
{
    /// <summary>
    /// Ordered list of rules to apply.
    /// </summary>
    public List<RuleConfiguration> Rules { get; set; } = [];

    /// <summary>
    /// Optional custom violation message. If set, blocked requests receive this message.
    /// </summary>
    public string? ViolationMessage { get; set; }
}
