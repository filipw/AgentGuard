using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Builders;
using AgentGuard.Core.Guardrails;
using AgentGuard.Core.Ledger;
using AgentGuard.Hosting.Configuration;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace AgentGuard.Hosting;

public sealed class AgentGuardOptions
{
    internal Action<GuardrailPolicyBuilder>? DefaultPolicyConfigurator { get; private set; }
    internal Dictionary<string, Action<GuardrailPolicyBuilder>> NamedPolicies { get; } = [];
    internal IGuardrailLedger? Ledger { get; private set; }

    public AgentGuardOptions DefaultPolicy(Action<GuardrailPolicyBuilder> configure) { DefaultPolicyConfigurator = configure; return this; }
    public AgentGuardOptions AddPolicy(string name, Action<GuardrailPolicyBuilder> configure) { NamedPolicies[name] = configure; return this; }

    /// <summary>
    /// Enables the tamper-evident decision ledger, recording one hash-chained entry per
    /// guardrail pipeline decision. The ledger is registered as a singleton and flows into
    /// every pipeline (including the MAF / Workflows / IChatClient adapters resolved from DI).
    /// </summary>
    /// <param name="ledger">The ledger to use.</param>
    public AgentGuardOptions UseDecisionLedger(IGuardrailLedger ledger) { Ledger = ledger; return this; }

    /// <summary>
    /// Enables a <see cref="HashChainLedger"/> decision ledger, optionally mirroring entries
    /// to an append-only JSONL file.
    /// </summary>
    /// <param name="jsonlFilePath">When set, each entry is also written to this JSONL file.</param>
    public AgentGuardOptions UseDecisionLedger(string? jsonlFilePath = null) { Ledger = new HashChainLedger(jsonlFilePath); return this; }
}

internal sealed class AgentGuardFactory : IAgentGuardFactory
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

    public AgentGuardFactory(AgentGuardConfiguration config, IServiceProvider serviceProvider)
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
    }

    public IGuardrailPolicy GetPolicy(string name) =>
        _policies.TryGetValue(name, out var p) ? p
        : throw new InvalidOperationException($"No guardrail policy named '{name}'. Available: {string.Join(", ", _policies.Keys)}");

    public IGuardrailPolicy GetDefaultPolicy() => _defaultPolicy;
}

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
        services.AddSingleton<IAgentGuardFactory, AgentGuardFactory>();
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
    public static IServiceCollection AddAgentGuard(this IServiceCollection services, IConfiguration configuration)
    {
        var config = configuration.Get<AgentGuardConfiguration>() ?? new AgentGuardConfiguration();
        services.AddSingleton<IAgentGuardFactory>(sp => new AgentGuardFactory(config, sp));
        services.AddSingleton(sp =>
            new GuardrailPipeline(
                sp.GetRequiredService<IAgentGuardFactory>().GetDefaultPolicy(),
                sp.GetRequiredService<ILogger<GuardrailPipeline>>(),
                sp.GetService<IGuardrailLedger>()));
        return services;
    }
}
