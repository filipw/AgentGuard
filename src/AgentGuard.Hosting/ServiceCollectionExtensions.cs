using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Builders;
using AgentGuard.Core.Guardrails;
using AgentGuard.Core.Ledger;
using AgentGuard.Hosting.Configuration;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace AgentGuard.Hosting;

/// <summary>Configures the policies and the optional decision ledger registered by <c>AddAgentGuard</c>.</summary>
public sealed class AgentGuardOptions
{
    internal Action<GuardrailPolicyBuilder>? DefaultPolicyConfigurator { get; private set; }
    internal Dictionary<string, Action<GuardrailPolicyBuilder>> NamedPolicies { get; } = [];
    internal IGuardrailLedger? Ledger { get; private set; }

    /// <summary>Configures the policy used when no name is given.</summary>
    /// <param name="configure">Builds the policy.</param>
    /// <returns>These options, for chaining.</returns>
    public AgentGuardOptions DefaultPolicy(Action<GuardrailPolicyBuilder> configure) { DefaultPolicyConfigurator = configure; return this; }

    /// <summary>Adds a named policy, resolvable through <see cref="IAgentGuardFactory.GetPolicy"/>.</summary>
    /// <param name="name">The policy name.</param>
    /// <param name="configure">Builds the policy.</param>
    /// <returns>These options, for chaining.</returns>
    public AgentGuardOptions AddPolicy(string name, Action<GuardrailPolicyBuilder> configure) { NamedPolicies[name] = configure; return this; }

    /// <summary>
    /// Enables the tamper-evident decision ledger, recording one hash-chained entry per
    /// guardrail pipeline decision. The ledger is registered as a singleton: the pipelines
    /// registered here and the MAF agent middleware (<c>UseAgentGuard</c> on an
    /// <c>AIAgentBuilder</c>) resolve it from DI; the <c>IChatClient</c> decorator and workflow
    /// executors take it as a parameter (<c>UseAgentGuard(..., ledger)</c>,
    /// <c>GuardedExecutorOptions.Ledger</c>).
    /// </summary>
    /// <param name="ledger">The ledger to use.</param>
    public AgentGuardOptions UseDecisionLedger(IGuardrailLedger ledger) { Ledger = ledger; return this; }

    /// <summary>
    /// Enables a <see cref="HashChainLedger"/> decision ledger, optionally mirroring entries
    /// to an append-only JSONL file.
    /// </summary>
    /// <param name="jsonlFilePath">
    /// When set, each entry is also written to this JSONL file. A file that already holds entries,
    /// such as one written before the process restarted, is continued rather than restarted, so it
    /// stays one verifiable chain.
    /// </param>
    /// <param name="maxInMemoryEntries">
    /// Caps the in-memory chain, evicting the oldest entries past the cap. Null (the default)
    /// retains every decision for the life of the process, which only suits a bounded run; set a
    /// cap for a long-lived service and mirror to <paramref name="jsonlFilePath"/> to keep the
    /// full chain on disk.
    /// </param>
    /// <returns>These options, for chaining.</returns>
    /// <exception cref="InvalidDataException">
    /// The last line of <paramref name="jsonlFilePath"/> is not an intact ledger entry, so its chain
    /// cannot be continued.
    /// </exception>
    public AgentGuardOptions UseDecisionLedger(string? jsonlFilePath = null, int? maxInMemoryEntries = null)
    {
        Ledger = new HashChainLedger(jsonlFilePath, maxInMemoryEntries);
        return this;
    }

    /// <summary>
    /// Enables a keyed <see cref="HashChainLedger"/> decision ledger: each entry's hash is an HMAC under
    /// <paramref name="key"/>, so someone who can rewrite the ledger file but does not hold the key cannot
    /// produce a chain that verifies. Without a key the chain only detects accidental corruption.
    /// </summary>
    /// <param name="key">The secret the chain is keyed with, at least <see cref="HashChainLedger.MinKeyLength"/> bytes. Keep it apart from the ledger file.</param>
    /// <param name="jsonlFilePath">
    /// When set, each entry is also written to this JSONL file; a file that already holds entries written
    /// with the same key is continued.
    /// </param>
    /// <param name="maxInMemoryEntries">Caps the in-memory chain; null retains every decision.</param>
    /// <exception cref="ArgumentException"><paramref name="key"/> is shorter than <see cref="HashChainLedger.MinKeyLength"/> bytes.</exception>
    /// <exception cref="InvalidDataException">
    /// The last line of <paramref name="jsonlFilePath"/> is not an intact ledger entry, so its chain
    /// cannot be continued.
    /// </exception>
    public AgentGuardOptions UseDecisionLedger(byte[] key, string? jsonlFilePath = null, int? maxInMemoryEntries = null)
    {
        Ledger = new HashChainLedger(key, jsonlFilePath, maxInMemoryEntries);
        return this;
    }
}

internal sealed partial class AgentGuardFactory : IAgentGuardFactory
{
    private readonly Dictionary<string, IGuardrailPolicy> _policies = [];
    private readonly IGuardrailPolicy _defaultPolicy;

    public AgentGuardFactory(AgentGuardOptions options)
    {
        if (options.DefaultPolicyConfigurator is not null)
        {
            var b = new GuardrailPolicyBuilder("default");
            options.DefaultPolicyConfigurator(b);
            _defaultPolicy = b.Build();
        }
        else _defaultPolicy = new GuardrailPolicy("default", [], null);

        foreach (var (name, cfg) in options.NamedPolicies)
        {
            var b = new GuardrailPolicyBuilder(name);
            cfg(b);
            _policies[name] = b.Build();
        }
    }

    /// <param name="config">The configuration that was read.</param>
    /// <param name="serviceProvider">Resolves what the configured rules depend on, and the logger.</param>
    /// <param name="source">Where <paramref name="config"/> was read from, for the no-rules warning.</param>
    public AgentGuardFactory(AgentGuardConfiguration config, IServiceProvider serviceProvider, IConfiguration? source = null)
    {
        if (config.DefaultPolicy is not null)
        {
            var b = new GuardrailPolicyBuilder("default");
            ConfigurationMapper.ApplyConfiguration(b, config.DefaultPolicy, serviceProvider);
            _defaultPolicy = b.Build();
        }
        else _defaultPolicy = new GuardrailPolicy("default", [], null);

        foreach (var (name, policyConfig) in config.Policies)
        {
            var b = new GuardrailPolicyBuilder(name);
            ConfigurationMapper.ApplyConfiguration(b, policyConfig, serviceProvider);
            _policies[name] = b.Build();
        }

        WarnAboutPoliciesWithoutRules(serviceProvider.GetService<ILoggerFactory>(), source);
    }

    // running without guardrails is allowed, but a policy with no rules lets everything through, and
    // that is also what a misnamed configuration section produces - so it is never left unsaid
    private void WarnAboutPoliciesWithoutRules(ILoggerFactory? loggerFactory, IConfiguration? source)
    {
        if (loggerFactory is null)
            return;

        var section = source as IConfigurationSection;
        var prefix = section is null ? "" : section.Path + ":";
        var hint = section is not null && !section.Exists()
            ? $" The configuration section '{section.Path}' does not exist."
            : "";

        var logger = loggerFactory.CreateLogger<AgentGuardFactory>();

        if (_defaultPolicy.Rules.Count == 0)
            LogPolicyWithoutRules(logger, "default policy", $"{prefix}{nameof(AgentGuardConfiguration.DefaultPolicy)}:{nameof(PolicyConfiguration.Rules)}", hint);

        foreach (var (name, policy) in _policies)
        {
            if (policy.Rules.Count == 0)
                LogPolicyWithoutRules(logger, $"policy '{name}'", $"{prefix}{nameof(AgentGuardConfiguration.Policies)}:{name}:{nameof(PolicyConfiguration.Rules)}", hint);
        }
    }

    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The AgentGuard {Policy} has no rules and lets every message through: no rules were found at '{RulesPath}'.{Hint}")]
    private static partial void LogPolicyWithoutRules(ILogger logger, string policy, string rulesPath, string hint);

    public IGuardrailPolicy GetPolicy(string name) =>
        _policies.TryGetValue(name, out var p) ? p
        : throw new InvalidOperationException($"No guardrail policy named '{name}'. Available: {string.Join(", ", _policies.Keys)}");

    public IGuardrailPolicy GetDefaultPolicy() => _defaultPolicy;
}

/// <summary>Registers AgentGuard with the dependency injection container.</summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers AgentGuard with code-based policy configuration.
    /// </summary>
    public static IServiceCollection AddAgentGuard(this IServiceCollection services, Action<AgentGuardOptions> configure)
    {
        var options = new AgentGuardOptions();
        configure(options);
        services.AddSingleton(options);

        // an explicit factory, not AddSingleton<IAgentGuardFactory, AgentGuardFactory>(): that form
        // relies on DI happening to pick the AgentGuardOptions constructor because
        // AgentGuardConfiguration is not registered. Register one for any other reason and the
        // code-based policies would silently vanish.
        services.AddSingleton<IAgentGuardFactory>(sp =>
            new AgentGuardFactory(sp.GetRequiredService<AgentGuardOptions>()));
        if (options.Ledger is not null)
            services.AddSingleton(options.Ledger);
        services.AddSingleton(sp =>
            new GuardrailPipeline(
                sp.GetRequiredService<IAgentGuardFactory>().GetDefaultPolicy(),
                sp.GetRequiredService<ILogger<GuardrailPipeline>>(),
                sp.GetService<IGuardrailLedger>()));
        return services;
    }

    /// <summary>
    /// Registers AgentGuard with policies loaded from <see cref="IConfiguration"/> (e.g. appsettings.json).
    /// LLM-based rules and ContentSafety rules resolve their dependencies (IChatClient, IContentSafetyClassifier) from DI.
    /// </summary>
    /// <remarks>
    /// The configuration is read when the policies are built, the first time <see cref="IAgentGuardFactory"/>
    /// or the registered <see cref="GuardrailPipeline"/> is resolved. A value that can't be read or a key
    /// that is not a known setting then throws an <see cref="InvalidOperationException"/>: a rule is never
    /// left out of a policy because one of its settings was mistyped. The same goes for a setting that
    /// belongs to a different rule type than the one it is written on.
    /// <para>
    /// Configuration that defines no rules is not an error - the policy is then empty and lets everything
    /// through - but each such policy is reported with a warning, through the container's
    /// <see cref="ILoggerFactory"/> when one is registered, that names the configuration path the rules
    /// were looked for at. Pass the section that holds <c>DefaultPolicy</c> and <c>Policies</c>, e.g.
    /// <c>configuration.GetSection("AgentGuard")</c>.
    /// </para>
    /// </remarks>
    public static IServiceCollection AddAgentGuard(this IServiceCollection services, IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        services.AddSingleton<IAgentGuardFactory>(sp =>
            new AgentGuardFactory(AgentGuardConfigurationReader.Read(configuration), sp, configuration));
        services.AddSingleton(sp =>
            new GuardrailPipeline(
                sp.GetRequiredService<IAgentGuardFactory>().GetDefaultPolicy(),
                sp.GetRequiredService<ILogger<GuardrailPipeline>>(),
                sp.GetService<IGuardrailLedger>()));
        return services;
    }
}
