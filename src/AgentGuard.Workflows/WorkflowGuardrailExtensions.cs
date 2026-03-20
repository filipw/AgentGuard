using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Builders;
using Microsoft.Agents.AI.Workflows;

namespace AgentGuard.Workflows;

/// <summary>
/// Extension methods for wrapping workflow executors with guardrails.
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
        var builder = new GuardrailPolicyBuilder($"guarded-{executor.Id}");
        configure(builder);
        return new GuardedExecutor<TInput>(executor, builder.Build(), options);
    }

    /// <summary>
    /// Wraps a void-return executor with input guardrails from a pre-built policy.
    /// </summary>
    public static GuardedExecutor<TInput> WithGuardrails<TInput>(
        this Executor<TInput> executor,
        IGuardrailPolicy policy,
        GuardedExecutorOptions? options = null)
    {
        return new GuardedExecutor<TInput>(executor, policy, options);
    }

    /// <summary>
    /// Wraps a typed-return executor with input and output guardrails configured via a policy builder.
    /// </summary>
    public static GuardedExecutor<TInput, TOutput> WithGuardrails<TInput, TOutput>(
        this Executor<TInput, TOutput> executor,
        Action<GuardrailPolicyBuilder> configure,
        GuardedExecutorOptions? options = null)
    {
        var builder = new GuardrailPolicyBuilder($"guarded-{executor.Id}");
        configure(builder);
        return new GuardedExecutor<TInput, TOutput>(executor, builder.Build(), options);
    }

    /// <summary>
    /// Wraps a typed-return executor with input and output guardrails from a pre-built policy.
    /// </summary>
    public static GuardedExecutor<TInput, TOutput> WithGuardrails<TInput, TOutput>(
        this Executor<TInput, TOutput> executor,
        IGuardrailPolicy policy,
        GuardedExecutorOptions? options = null)
    {
        return new GuardedExecutor<TInput, TOutput>(executor, policy, options);
    }
}
