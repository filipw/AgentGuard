using AgentGuard.Core.Abstractions;

namespace AgentGuard.Core.Rules;

/// <summary>Helpers for working with <see cref="IGuardrailRule"/> instances.</summary>
public static class GuardrailRuleExtensions
{
    /// <summary>
    /// Returns the rule behind any <see cref="ConditionalGuardrailRule"/> gates (the <c>.When()</c> /
    /// <c>.Unless()</c> wrappers), unwrapping nested gates. Any other rule is returned as-is.
    /// </summary>
    /// <remarks>
    /// A gate hides the type of the rule it wraps, so code that looks for a particular kind of rule
    /// (a tool-result rule, a streaming-aware rule, an LLM judge) must unwrap first. Keep evaluating the
    /// original rule, though - the gate is what applies the predicate.
    /// </remarks>
    /// <param name="rule">The rule to unwrap.</param>
    /// <returns>The innermost rule.</returns>
    public static IGuardrailRule Unwrap(this IGuardrailRule rule)
    {
        ArgumentNullException.ThrowIfNull(rule);

        while (rule is ConditionalGuardrailRule conditional)
            rule = conditional.InnerRule;

        return rule;
    }
}
