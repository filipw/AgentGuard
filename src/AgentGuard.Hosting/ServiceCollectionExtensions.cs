using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Builders;
using AgentGuard.Core.Guardrails;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace AgentGuard.Hosting;

public sealed class AgentGuardOptions
{
    internal Action<GuardrailPolicyBuilder>? DefaultPolicyConfigurator { get; private set; }
    internal Dictionary<string, Action<GuardrailPolicyBuilder>> NamedPolicies { get; } = [];

    public AgentGuardOptions DefaultPolicy(Action<GuardrailPolicyBuilder> configure) { DefaultPolicyConfigurator = configure; return this; }
    public AgentGuardOptions AddPolicy(string name, Action<GuardrailPolicyBuilder> configure) { NamedPolicies[name] = configure; return this; }
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

    public IGuardrailPolicy GetPolicy(string name) =>
        _policies.TryGetValue(name, out var p) ? p
        : throw new InvalidOperationException($"No guardrail policy named '{name}'. Available: {string.Join(", ", _policies.Keys)}");

    public IGuardrailPolicy GetDefaultPolicy() => _defaultPolicy;
}

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddAgentGuard(this IServiceCollection services, Action<AgentGuardOptions> configure)
    {
        var options = new AgentGuardOptions();
        configure(options);
        services.AddSingleton(options);
        services.AddSingleton<IAgentGuardFactory, AgentGuardFactory>();
        services.AddSingleton(sp =>
            new GuardrailPipeline(sp.GetRequiredService<IAgentGuardFactory>().GetDefaultPolicy(), sp.GetRequiredService<ILogger<GuardrailPipeline>>()));
        return services;
    }
}
