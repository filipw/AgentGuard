using AgentGuard.Core.Abstractions;

namespace AgentGuard.Core.Rules;

/// <summary>
/// Wraps another <see cref="IGuardrailRule"/> with a runtime predicate that decides, per
/// evaluation, whether the inner rule should run. When the predicate returns <c>false</c> the
/// inner rule is skipped and the result is <see cref="GuardrailResult.Passed()"/>.
/// <para>
/// Use this to enable or disable a rule dynamically based on request context. For example, the
/// English-centric Defender classifier can be skipped for non-English users. The predicate may
/// read the <see cref="GuardrailContext"/> (Properties, AgentName, Messages) and/or capture ambient
/// services in its closure - e.g. an <c>IHttpContextAccessor</c> to inspect the request's
/// <c>ClaimsPrincipal</c> or detected locale. Ambient accessors flow correctly because the pipeline
/// runs on the request's async context.
/// </para>
/// <para>
/// <see cref="Name"/>, <see cref="Phase"/> and <see cref="Order"/> are delegated to the inner rule,
/// so execution order and telemetry are unchanged.
/// </para>
/// </summary>
public sealed class ConditionalGuardrailRule : IGuardrailRule
{
    private readonly IGuardrailRule _inner;
    private readonly Func<GuardrailContext, CancellationToken, ValueTask<bool>> _shouldRun;

    /// <summary>
    /// Creates a conditional rule with an asynchronous predicate.
    /// </summary>
    /// <param name="inner">The rule to gate.</param>
    /// <param name="shouldRun">Returns true when <paramref name="inner"/> should evaluate.</param>
    public ConditionalGuardrailRule(
        IGuardrailRule inner,
        Func<GuardrailContext, CancellationToken, ValueTask<bool>> shouldRun)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
        _shouldRun = shouldRun ?? throw new ArgumentNullException(nameof(shouldRun));
    }

    /// <summary>
    /// Creates a conditional rule with a synchronous predicate.
    /// </summary>
    /// <param name="inner">The rule to gate.</param>
    /// <param name="shouldRun">Returns true when <paramref name="inner"/> should evaluate.</param>
    public ConditionalGuardrailRule(IGuardrailRule inner, Func<GuardrailContext, bool> shouldRun)
        : this(inner, Wrap(shouldRun))
    {
    }

    /// <summary>The wrapped rule.</summary>
    public IGuardrailRule InnerRule => _inner;

    /// <inheritdoc />
    public string Name => _inner.Name;

    /// <inheritdoc />
    public GuardrailPhase Phase => _inner.Phase;

    /// <inheritdoc />
    public int Order => _inner.Order;

    /// <inheritdoc />
    public async ValueTask<GuardrailResult> EvaluateAsync(
        GuardrailContext context, CancellationToken cancellationToken = default)
    {
        if (!await _shouldRun(context, cancellationToken).ConfigureAwait(false))
            return GuardrailResult.Passed();

        return await _inner.EvaluateAsync(context, cancellationToken).ConfigureAwait(false);
    }

    private static Func<GuardrailContext, CancellationToken, ValueTask<bool>> Wrap(Func<GuardrailContext, bool> predicate)
    {
        ArgumentNullException.ThrowIfNull(predicate);
        return (ctx, _) => ValueTask.FromResult(predicate(ctx));
    }
}
