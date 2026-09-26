using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Builders;
using Microsoft.Agents.AI.Workflows;

namespace AgentGuard.AgentFramework.Workflows;

/// <summary>
/// Extension methods for wrapping workflow executors with guardrails. The returned executor, with the id
/// <c>guarded-{executor id}</c>, replaces the original in the workflow and keeps its protocol and lifecycle.
/// </summary>
public static class WorkflowGuardrailExtensions
{
    /// <summary>
    /// Wraps a void-return executor with input guardrails configured via a policy builder.
    /// </summary>
    public static GuardedExecutor<TInput> WithGuardrails<TInput>(
        this Executor<TInput> executor,
        Action<GuardrailPolicyBuilder> configure,
        GuardedExecutorOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(executor);
        ArgumentNullException.ThrowIfNull(configure);

        var builder = new GuardrailPolicyBuilder($"guarded-{executor.Id}");
        configure(builder);
        return GuardedExecutor<TInput>.Create(executor, builder.Build(), options);
    }

    /// <summary>
    /// Wraps a void-return executor with input guardrails from a pre-built policy.
    /// </summary>
    public static GuardedExecutor<TInput> WithGuardrails<TInput>(
        this Executor<TInput> executor,
        IGuardrailPolicy policy,
        GuardedExecutorOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(executor);
        ArgumentNullException.ThrowIfNull(policy);

        return GuardedExecutor<TInput>.Create(executor, policy, options);
    }

    /// <summary>
    /// Wraps a typed-return executor with input and output guardrails configured via a policy builder.
    /// </summary>
    public static GuardedExecutor<TInput, TOutput> WithGuardrails<TInput, TOutput>(
        this Executor<TInput, TOutput> executor,
        Action<GuardrailPolicyBuilder> configure,
        GuardedExecutorOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(executor);
        ArgumentNullException.ThrowIfNull(configure);

        var builder = new GuardrailPolicyBuilder($"guarded-{executor.Id}");
        configure(builder);
        return GuardedExecutor<TInput, TOutput>.Create(executor, builder.Build(), options);
    }

    /// <summary>
    /// Wraps a typed-return executor with input and output guardrails from a pre-built policy.
    /// </summary>
    public static GuardedExecutor<TInput, TOutput> WithGuardrails<TInput, TOutput>(
        this Executor<TInput, TOutput> executor,
        IGuardrailPolicy policy,
        GuardedExecutorOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(executor);
        ArgumentNullException.ThrowIfNull(policy);

        return GuardedExecutor<TInput, TOutput>.Create(executor, policy, options);
    }
}
