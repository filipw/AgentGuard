using System.Collections;
using System.Reflection;

namespace AgentGuard.Core.Configuration;

/// <summary>
/// Checks that a configured rule entry carries only settings its rule type reads.
/// </summary>
/// <remarks>
/// <see cref="RuleConfiguration"/> holds the settings of every rule type side by side, so a setting
/// that belongs to another type binds without complaint and would then simply be ignored - the rule
/// would run with a default the configuration appears to override. The built-in rule types are checked
/// when a policy is built from configuration; an <see cref="IGuardrailRuleFactory"/> knows which
/// settings its own rule reads and calls <see cref="EnsureOnly"/> itself.
/// </remarks>
public static class RuleSettings
{
    private static readonly PropertyInfo[] Settings = typeof(RuleConfiguration)
        .GetProperties(BindingFlags.Public | BindingFlags.Instance)
        .Where(property => property.Name != nameof(RuleConfiguration.Type))
        .ToArray();

    /// <summary>Throws when <paramref name="rule"/> sets anything other than <paramref name="accepted"/>.</summary>
    /// <param name="rule">The configured rule entry.</param>
    /// <param name="accepted">The names of the <see cref="RuleConfiguration"/> properties the rule type reads.</param>
    /// <exception cref="InvalidOperationException">A setting the rule type does not read has a value.</exception>
    public static void EnsureOnly(RuleConfiguration rule, params string[] accepted)
    {
        ArgumentNullException.ThrowIfNull(rule);
        ArgumentNullException.ThrowIfNull(accepted);

        foreach (var setting in Settings)
        {
            if (accepted.Contains(setting.Name, StringComparer.Ordinal) || !IsSet(setting.GetValue(rule)))
                continue;

            var names = accepted.Length == 0
                ? "This rule type has no settings."
                : $"Its settings are: {string.Join(", ", accepted.Order(StringComparer.Ordinal))}.";

            throw new InvalidOperationException(
                $"{rule.Type}: {setting.Name} is not a setting of this rule type. {names}");
        }
    }

    // an empty list is what the binder leaves for a key with nothing under it; a string is a value
    private static bool IsSet(object? value) => value switch
    {
        null => false,
        string => true,
        ICollection collection => collection.Count > 0,
        _ => true,
    };
}
