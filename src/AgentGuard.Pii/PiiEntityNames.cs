using System.Reflection;
using TasmanianDevil;

namespace AgentGuard.Pii;

/// <summary>
/// Checks configured PII entity type names against the names a detector can actually produce.
/// </summary>
/// <remarks>
/// An entity name nothing recognizes is not an error to the detection engine: it simply never
/// matches, and a misspelled <c>EMAIL_ADRESS</c> quietly switches the detection of e-mail addresses
/// off. Resolving the names when a rule is built turns that into an <see cref="ArgumentException"/>.
/// </remarks>
public static class PiiEntityNames
{
    /// <summary>
    /// The engine's canonical entity type names: the <see cref="PiiEntities"/> constants, such as
    /// <c>PERSON</c> and <c>EMAIL_ADDRESS</c>.
    /// </summary>
    public static IReadOnlyList<string> Canonical { get; } = typeof(PiiEntities)
        .GetFields(BindingFlags.Public | BindingFlags.Static)
        .Where(field => field is { IsLiteral: true } && field.FieldType == typeof(string))
        .Select(field => (string)field.GetRawConstantValue()!)
        .ToArray();

    /// <summary>
    /// Maps each of <paramref name="names"/> onto the accepted name it stands for, ignoring case and
    /// surrounding whitespace, and rejects any name that stands for none.
    /// </summary>
    /// <param name="names">The configured entity names.</param>
    /// <param name="accepted">The names the detector can produce, in the spelling it uses.</param>
    /// <param name="aliases">
    /// Other spellings that are accepted too, each mapped to the accepted name it stands for - for
    /// example a service's own category names (<c>Person</c> for <c>PERSON</c>). An alias whose
    /// target is not in <paramref name="accepted"/> is accepted as that target all the same.
    /// </param>
    /// <param name="parameterName">The parameter name reported on the exception.</param>
    /// <returns>The resolved names, without duplicates, in the order they were given.</returns>
    /// <exception cref="ArgumentException">
    /// A name is neither an accepted name nor an alias. The message lists the accepted names.
    /// </exception>
    public static IReadOnlyList<string> Resolve(
        IEnumerable<string> names,
        IEnumerable<string> accepted,
        IReadOnlyDictionary<string, string>? aliases = null,
        string? parameterName = null)
    {
        ArgumentNullException.ThrowIfNull(names);
        ArgumentNullException.ThrowIfNull(accepted);

        var byName = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var name in accepted)
            byName.TryAdd(name, name);

        var byAlias = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (alias, target) in aliases ?? new Dictionary<string, string>())
            byAlias.TryAdd(alias, target);

        var resolved = new List<string>();
        foreach (var name in names)
        {
            var key = name?.Trim() ?? "";
            if (!byName.TryGetValue(key, out var match) && !byAlias.TryGetValue(key, out match))
                throw Unknown(name, byName.Values, byAlias, parameterName);

            if (!resolved.Contains(match, StringComparer.Ordinal))
                resolved.Add(match);
        }

        return resolved;
    }

    private static ArgumentException Unknown(
        string? name, IEnumerable<string> accepted, Dictionary<string, string> aliases, string? parameterName)
    {
        var message = $"'{name}' is not a PII entity type the detector finds. Accepted: " +
            string.Join(", ", accepted.Order(StringComparer.Ordinal)) + ".";

        if (aliases.Count > 0)
        {
            message += " Also accepted: " +
                string.Join(", ", aliases.OrderBy(a => a.Key, StringComparer.Ordinal).Select(a => $"{a.Key} (for {a.Value})")) + ".";
        }

        return new ArgumentException(message, parameterName);
    }
}
