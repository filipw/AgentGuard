using System.Text;
using AgentGuard.Pii;
using TasmanianDevil;
using TasmanianDevil.Anonymizer;
using TasmanianDevil.Anonymizer.Operators;
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;

namespace AgentGuard.AgentFramework;

/// <summary>
/// Adds reversible PII protection to a MAF agent: detected PII in the user's message is encrypted
/// (AES) into opaque tokens before the inner agent and the model provider ever see it, and those
/// tokens are decrypted back to the original values in the agent's response. The model reasons over
/// placeholders, never the raw PII, while the end user still sees the real values.
/// <para>
/// This is the cross-phase round-trip the per-message guardrail rules cannot express on their own:
/// the input and output guardrail phases run on separate contexts, so a rule pair has no shared place
/// to carry the encryption tokens. This middleware holds them in the per-invocation closure instead.
/// </para>
/// </summary>
public static class PiiReversibleRedactionExtensions
{
    private const string EncryptOperatorName = "encrypt";

    /// <summary>
    /// Wraps the agent so PII in each request is encrypted before the inner agent runs and decrypted
    /// back in the response. Restoration is by exact token match, so it survives the model echoing the
    /// tokens at different positions; tokens the model paraphrases or drops are simply not restored.
    /// </summary>
    /// <param name="builder">The MAF agent builder.</param>
    /// <param name="key">AES key (16, 24, or 32 bytes when UTF-8 encoded - 128/192/256-bit).</param>
    /// <param name="options">
    /// Optional detection configuration (entities, countries, language, threshold, allow-list). Any
    /// <see cref="PiiOptions.Operators"/>/<see cref="PiiOptions.Replacement"/> are ignored - this
    /// middleware always anonymizes with the reversible <c>encrypt</c> operator.
    /// </param>
    /// <exception cref="ArgumentException">Thrown when <paramref name="key"/> is not a valid AES key length.</exception>
    public static AIAgentBuilder UsePiiReversibleRedaction(
        this AIAgentBuilder builder,
        string key,
        PiiOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrEmpty(key);

        var keyBytes = Encoding.UTF8.GetBytes(key);
        if (!AesCipher.IsValidKeySize(keyBytes))
            throw new ArgumentException("key must be 16, 24, or 32 bytes (128/192/256-bit) when UTF-8 encoded.", nameof(key));

        var engine = new PiiEngine(BuildEncryptOptions(options, key));

        return builder.Use(
            runFunc: async (messages, session, runOptions, innerAgent, ct) =>
            {
                var list = messages as IList<ChatMessage> ?? messages.ToList();
                var (processed, restore) = Protect(engine, keyBytes, list);

                var response = await innerAgent.RunAsync(processed, session, runOptions, ct);

                return restore.Count == 0 ? response : RestoreResponse(response, restore);
            },
            runStreamingFunc: (messages, session, runOptions, innerAgent, ct) =>
            {
                var list = messages as IList<ChatMessage> ?? messages.ToList();
                var (processed, restore) = Protect(engine, keyBytes, list);

                return RestoreStream(innerAgent.RunStreamingAsync(processed, session, runOptions, ct), restore);
            });
    }

    // encrypts PII in the last user message; returns the (possibly rewritten) message list and the
    // token -> original map used to restore the response. on no PII, the list is returned unchanged.
    private static (IList<ChatMessage> Messages, IReadOnlyDictionary<string, string> Restore) Protect(
        PiiEngine engine,
        byte[] keyBytes,
        IList<ChatMessage> messages)
    {
        var last = messages.Count > 0 ? messages[^1] : null;
        var text = last?.Text;
        if (last is null || string.IsNullOrEmpty(text))
            return (messages, EmptyRestore);

        var deid = engine.Deidentify(text);
        if (deid.Items.Count == 0)
            return (messages, EmptyRestore);

        var restore = BuildRestoreMap(deid.Items, keyBytes);
        if (restore.Count == 0)
            return (messages, EmptyRestore);

        var rewritten = new List<ChatMessage>(messages);
        rewritten[^1] = new ChatMessage(last.Role, deid.AnonymizedText);
        return (rewritten, restore);
    }

    private static readonly IReadOnlyDictionary<string, string> EmptyRestore =
        new Dictionary<string, string>(StringComparer.Ordinal);

    // maps each distinct ciphertext token back to its decrypted original value.
    private static Dictionary<string, string> BuildRestoreMap(IReadOnlyList<OperatorResult> items, byte[] keyBytes)
    {
        var map = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var item in items)
        {
            if (!string.Equals(item.Operator, EncryptOperatorName, StringComparison.Ordinal))
                continue;
            if (!map.ContainsKey(item.Text))
                map[item.Text] = AesCipher.Decrypt(keyBytes, item.Text);
        }

        return map;
    }

    private static AgentResponse RestoreResponse(AgentResponse response, IReadOnlyDictionary<string, string> restore)
    {
        var restored = new List<ChatMessage>(response.Messages.Count);
        foreach (var message in response.Messages)
        {
            var text = message.Text;
            if (!string.IsNullOrEmpty(text))
            {
                var newText = ApplyRestore(text, restore);
                if (!string.Equals(newText, text, StringComparison.Ordinal))
                {
                    restored.Add(new ChatMessage(message.Role, newText));
                    continue;
                }
            }

            restored.Add(message);
        }

        return new AgentResponse(restored);
    }

    private static async IAsyncEnumerable<AgentResponseUpdate> RestoreStream(
        IAsyncEnumerable<AgentResponseUpdate> updates,
        IReadOnlyDictionary<string, string> restore)
    {
        await foreach (var update in updates)
        {
            // best-effort: tokens are restored per update, so a token split across two chunks is
            // not restored. Use the non-streaming path when guaranteed restoration matters.
            var text = update.Text;
            if (restore.Count == 0 || string.IsNullOrEmpty(text))
            {
                yield return update;
                continue;
            }

            var newText = ApplyRestore(text, restore);
            yield return string.Equals(newText, text, StringComparison.Ordinal)
                ? update
                : new AgentResponseUpdate(update.Role ?? ChatRole.Assistant, newText);
        }
    }

    private static string ApplyRestore(string text, IReadOnlyDictionary<string, string> restore)
    {
        foreach (var (token, original) in restore)
        {
            if (text.Contains(token, StringComparison.Ordinal))
                text = text.Replace(token, original, StringComparison.Ordinal);
        }

        return text;
    }

    // clones the detection-relevant options and forces the reversible encrypt operator.
    private static PiiOptions BuildEncryptOptions(PiiOptions? source, string key)
    {
        var encrypt = new Dictionary<string, OperatorConfig>
        {
            ["DEFAULT"] = new(EncryptOperatorName, new Dictionary<string, object> { [OperatorParams.Key] = key }),
        };

        if (source is null)
            return new PiiOptions { Operators = encrypt };

        return new PiiOptions
        {
            Entities = source.Entities,
            Countries = source.Countries,
            Language = source.Language,
            ScoreThreshold = source.ScoreThreshold,
            ContextMatchingMode = source.ContextMatchingMode,
            AllowList = source.AllowList,
            AllowListMatch = source.AllowListMatch,
            ConflictResolution = source.ConflictResolution,
            Operators = encrypt,
        };
    }
}
