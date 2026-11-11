using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Guardrails;
using AgentGuard.Hosting;
using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;

namespace AgentGuard.Integration.Tests;

/// <summary>
/// A policy loaded from configuration that ends up with no rules lets everything through. That is
/// allowed - an application may run without guardrails - but it is said out loud, with the place the
/// configuration was read from, so a misnamed section does not pass for a configured one.
/// </summary>
public class ConfigurationEmptyPolicyTests
{
    private static IConfigurationRoot BuildConfig(Dictionary<string, string?> values) =>
        new ConfigurationBuilder().AddInMemoryCollection(values).Build();

    private static (ServiceProvider Provider, CapturingLoggerProvider Logs) BuildProvider(IConfiguration configuration)
    {
        var logs = new CapturingLoggerProvider();
        var services = new ServiceCollection();
        services.AddLogging(logging => logging.AddProvider(logs).SetMinimumLevel(LogLevel.Trace));
        services.AddAgentGuard(configuration);
        return (services.BuildServiceProvider(), logs);
    }

    [Fact]
    public void ShouldWarnThatTheDefaultPolicyLetsEverythingThrough_WhenThereIsNoConfiguration()
    {
        var (provider, logs) = BuildProvider(BuildConfig([]));

        var policy = provider.GetRequiredService<IAgentGuardFactory>().GetDefaultPolicy();

        policy.Rules.Should().BeEmpty();
        logs.Warnings.Should().ContainSingle()
            .Which.Should().Contain("default policy").And.Contain("no rules").And.Contain("DefaultPolicy:Rules");
    }

    [Fact]
    public void ShouldNameTheMissingSection_WhenTheConfigurationSectionDoesNotExist()
    {
        var root = BuildConfig(new Dictionary<string, string?>
        {
            ["AgentGuard:DefaultPolicy:Rules:0:Type"] = "PromptInjection",
        });
        var (provider, logs) = BuildProvider(root.GetSection("AgentGaurd"));

        var policy = provider.GetRequiredService<IAgentGuardFactory>().GetDefaultPolicy();

        policy.Rules.Should().BeEmpty();
        logs.Warnings.Should().ContainSingle()
            .Which.Should().Contain("'AgentGaurd'").And.Contain("does not exist").And.Contain("AgentGaurd:DefaultPolicy:Rules");
    }

    [Fact]
    public void ShouldNameTheNestedPath_WhenTheSectionExistsButHasNoRules()
    {
        var root = BuildConfig(new Dictionary<string, string?>
        {
            ["Guardrails:AgentGuard:DefaultPolicy:ViolationMessage"] = "Blocked.",
        });
        var (provider, logs) = BuildProvider(root.GetSection("Guardrails:AgentGuard"));

        var policy = provider.GetRequiredService<IAgentGuardFactory>().GetDefaultPolicy();

        policy.Rules.Should().BeEmpty();
        logs.Warnings.Should().ContainSingle()
            .Which.Should().Contain("Guardrails:AgentGuard:DefaultPolicy:Rules").And.NotContain("does not exist");
    }

    [Fact]
    public void ShouldWarnAboutTheDefaultPolicy_WhenOnlyNamedPoliciesAreConfigured()
    {
        var (provider, logs) = BuildProvider(BuildConfig(new Dictionary<string, string?>
        {
            ["Policies:strict:Rules:0:Type"] = "PromptInjection",
        }));

        var factory = provider.GetRequiredService<IAgentGuardFactory>();

        factory.GetPolicy("strict").Rules.Should().ContainSingle();
        logs.Warnings.Should().ContainSingle().Which.Should().Contain("default policy");
    }

    [Fact]
    public void ShouldWarnAboutANamedPolicy_WhenItHasNoRules()
    {
        var (provider, logs) = BuildProvider(BuildConfig(new Dictionary<string, string?>
        {
            ["DefaultPolicy:Rules:0:Type"] = "PromptInjection",
            ["Policies:strict:ViolationMessage"] = "Blocked.",
        }));

        var factory = provider.GetRequiredService<IAgentGuardFactory>();

        factory.GetPolicy("strict").Rules.Should().BeEmpty();
        logs.Warnings.Should().ContainSingle()
            .Which.Should().Contain("policy 'strict'").And.Contain("Policies:strict:Rules");
    }

    [Fact]
    public void ShouldNotWarn_WhenEveryPolicyHasRules()
    {
        var (provider, logs) = BuildProvider(BuildConfig(new Dictionary<string, string?>
        {
            ["DefaultPolicy:Rules:0:Type"] = "PromptInjection",
            ["Policies:strict:Rules:0:Type"] = "Secrets",
        }));

        provider.GetRequiredService<IAgentGuardFactory>();

        logs.Warnings.Should().BeEmpty();
    }

    [Fact]
    public void ShouldWarnOnce_WhenTheFactoryAndThePipelineAreBothResolved()
    {
        var (provider, logs) = BuildProvider(BuildConfig([]));

        provider.GetRequiredService<GuardrailPipeline>();
        provider.GetRequiredService<IAgentGuardFactory>();

        logs.Warnings.Should().ContainSingle();
    }

    [Fact]
    public void ShouldBuildTheEmptyPolicy_WhenNoLoggingIsRegistered()
    {
        var services = new ServiceCollection();
        services.AddAgentGuard(BuildConfig([]));
        var provider = services.BuildServiceProvider();

        var policy = provider.GetRequiredService<IAgentGuardFactory>().GetDefaultPolicy();

        policy.Rules.Should().BeEmpty();
    }

    private sealed class CapturingLoggerProvider : ILoggerProvider
    {
        private readonly List<string> _warnings = [];

        public IReadOnlyList<string> Warnings
        {
            get
            {
                lock (_warnings)
                    return [.. _warnings];
            }
        }

        public ILogger CreateLogger(string categoryName) => new CapturingLogger(this);

        public void Dispose()
        {
        }

        private sealed class CapturingLogger(CapturingLoggerProvider owner) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(
                LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            {
                if (logLevel != LogLevel.Warning)
                    return;

                lock (owner._warnings)
                    owner._warnings.Add(formatter(state, exception));
            }
        }
    }
}
