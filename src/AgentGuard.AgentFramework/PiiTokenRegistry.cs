using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Agents.AI;

namespace AgentGuard.AgentFramework;

/// <summary>
/// The tokens reversible redaction minted for a session, kept in the session's
/// <see cref="AgentSession.StateBag"/> so that a later turn can restore the tokens its history replays to the
/// model. A token that isn't listed there, or in the current request, is never restored.
/// </summary>
/// <remarks>
/// <para>
/// Only the ciphertext tokens are stored, never the values they encrypt, as a JSON array of strings, so the list
/// is serialized with the session. It keeps the most recent <see cref="Capacity"/> tokens, oldest first.
/// </para>
/// <para>
/// Recording reads the list, adds to a copy and writes the copy back. Two runs on the same session at the same
/// time can each overwrite the other's addition; the tokens of the run that lost are then not restored in later
/// turns. The list itself is never modified in place, so a run still reading an older copy is not affected.
/// </para>
/// </remarks>
internal static class PiiTokenRegistry
{
    /// <summary>The <see cref="AgentSession.StateBag"/> key the tokens are stored under.</summary>
    public const string StateKey = "AgentGuard.PiiReversibleRedaction.Tokens";

    /// <summary>How many tokens a session keeps; the oldest go first.</summary>
    public const int Capacity = 4096;

    /// <summary>Returns the tokens recorded for <paramref name="session"/>, oldest first; none without a session.</summary>
    /// <param name="session">The run's session, if it has one.</param>
    /// <returns>The recorded tokens.</returns>
    public static IReadOnlyList<string> Read(AgentSession? session)
    {
        if (session is null)
            return [];

        try
        {
            return session.StateBag.TryGetValue<string[]>(StateKey, out var tokens, PiiTokenRegistryJsonContext.Default.Options)
                ? tokens ?? []
                : [];
        }
        catch (JsonException)
        {
            // state that isn't a list of tokens restores nothing, and the next recording replaces it
            return [];
        }
    }

    /// <summary>
    /// Adds <paramref name="tokens"/> to the tokens recorded for <paramref name="session"/>, keeping the most recent
    /// <see cref="Capacity"/>.
    /// </summary>
    /// <param name="session">The run's session.</param>
    /// <param name="tokens">The tokens minted for the run's request.</param>
    public static void Record(AgentSession session, IEnumerable<string> tokens)
    {
        var recorded = Read(session);
        var known = new HashSet<string>(recorded, StringComparer.Ordinal);

        var added = tokens.Where(known.Add).ToList();
        if (added.Count == 0)
            return;

        var all = recorded.Concat(added);
        var excess = recorded.Count + added.Count - Capacity;

        session.StateBag.SetValue(
            StateKey,
            (excess > 0 ? all.Skip(excess) : all).ToArray(),
            PiiTokenRegistryJsonContext.Default.Options);
    }
}

/// <summary>Serializes the token list without reflection, so it works in trimmed and native AOT apps.</summary>
[JsonSerializable(typeof(string[]))]
internal sealed partial class PiiTokenRegistryJsonContext : JsonSerializerContext;
