using System.Runtime.CompilerServices;
using System.Text;
using AgentGuard.Core.Guardrails;
using TasmanianDevil;
using TasmanianDevil.Anonymizer;
using TasmanianDevil.Anonymizer.Operators;
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;

namespace AgentGuard.AgentFramework;

/// <summary>
/// Adds reversible PII protection to a MAF agent: detected PII in every message of the request is
/// encrypted (AES) into opaque tokens before the inner agent and the model provider ever see it, and those
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

        // the engine built here lives as long as the agent, and AIAgentBuilder offers no disposal
        // hook to release it. That is fine for the default fully-offline configuration, which owns
        // nothing but managed state - but an engine carrying a remote detector or an ONNX
        // recognizer needs a lifetime the caller controls, which is what the overload below is for.
        var engine = new PiiEngine(BuildEncryptOptions(options, key));

        return builder.UsePiiReversibleRedaction(engine, key);
    }

    /// <summary>
    /// Wraps the agent using a <see cref="PiiEngine"/> the caller constructed and continues to own.
    /// </summary>
    /// <remarks>
    /// Use this when the engine holds resources - a remote detector's <see cref="System.Net.Http.HttpClient"/>,
    /// an ONNX NER session - or when one engine should be shared across several agents. The engine
    /// is never disposed here; its lifetime stays with whoever built it. Detection runs on the engine's
    /// asynchronous path, so remote and Azure detectors take part. Configure it with the reversible
    /// <c>encrypt</c> operator, which <see cref="UsePiiReversibleRedaction(AIAgentBuilder, string, PiiOptions?)"/>
    /// does for you: spans anonymized by any other operator still never reach the model, but they can't
    /// be restored in the response.
    /// </remarks>
    /// <param name="builder">The MAF agent builder.</param>
    /// <param name="engine">A caller-owned engine, normally configured with the <c>encrypt</c> operator.</param>
    /// <param name="key">The same AES key the engine encrypts with, used to decrypt on the way back.</param>
    /// <exception cref="ArgumentException">Thrown when <paramref name="key"/> is not a valid AES key length.</exception>
    public static AIAgentBuilder UsePiiReversibleRedaction(
        this AIAgentBuilder builder,
        PiiEngine engine,
        string key)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(engine);
        ArgumentException.ThrowIfNullOrEmpty(key);

        var keyBytes = Encoding.UTF8.GetBytes(key);
        if (!AesCipher.IsValidKeySize(keyBytes))
            throw new ArgumentException("key must be 16, 24, or 32 bytes (128/192/256-bit) when UTF-8 encoded.", nameof(key));

        return builder.Use(
            runFunc: async (messages, session, runOptions, innerAgent, ct) =>
            {
                var list = messages as IReadOnlyList<ChatMessage> ?? messages.ToList();
                var (processed, restore) = await ProtectAsync(engine, keyBytes, list, ct).ConfigureAwait(false);

                var response = await innerAgent.RunAsync(processed, session, runOptions, ct).ConfigureAwait(false);

                return restore.Count == 0 ? response : RestoreResponse(response, restore);
            },
            runStreamingFunc: (messages, session, runOptions, innerAgent, ct) =>
                ProtectAndStreamAsync(engine, keyBytes, messages, session, runOptions, innerAgent, ct));
    }

    private static async IAsyncEnumerable<AgentResponseUpdate> ProtectAndStreamAsync(
        PiiEngine engine,
        byte[] keyBytes,
        IEnumerable<ChatMessage> messages,
        AgentSession? session,
        AgentRunOptions? runOptions,
        AIAgent innerAgent,
        [EnumeratorCancellation] CancellationToken ct)
    {
        var list = messages as IReadOnlyList<ChatMessage> ?? messages.ToList();
        var (processed, restore) = await ProtectAsync(engine, keyBytes, list, ct).ConfigureAwait(false);

        await foreach (var update in RestoreStream(innerAgent.RunStreamingAsync(processed, session, runOptions, ct), restore)
            .WithCancellation(ct).ConfigureAwait(false))
        {
            yield return update;
        }
    }

    // anonymizes PII in every text-bearing message of the request, including history a client sends
    // back and context-provider messages, and returns the token -> original map used to restore the
    // response. Detection runs on the engine's asynchronous path, which is what runs remote and
    // Azure detectors.
    private static async Task<(IReadOnlyList<ChatMessage> Messages, IReadOnlyDictionary<string, string> Restore)> ProtectAsync(
        PiiEngine engine,
        byte[] keyBytes,
        IReadOnlyList<ChatMessage> messages,
        CancellationToken ct)
    {
        List<ChatMessage>? rewritten = null;
        Dictionary<string, string>? restore = null;

        for (var i = 0; i < messages.Count; i++)
        {
            var text = messages[i].Text;
            if (string.IsNullOrEmpty(text))
                continue;

            var deid = await engine.DeidentifyAsync(text, ct).ConfigureAwait(false);
            if (deid.Items.Count == 0)
                continue;

            // the anonymized text always goes on, even for spans an engine's non-reversible operator
            // produced: only encrypt tokens can be restored, but nothing detected may reach the model
            (rewritten ??= [.. messages])[i] = GuardrailChatContent.WithText(messages[i], deid.AnonymizedText);
            AddRestoreEntries(restore ??= new Dictionary<string, string>(StringComparer.Ordinal), deid.Items, keyBytes);
        }

        return (rewritten ?? messages, restore ?? EmptyRestore);
    }

    private static readonly IReadOnlyDictionary<string, string> EmptyRestore =
        new Dictionary<string, string>(StringComparer.Ordinal);

    // maps each distinct ciphertext token back to its decrypted original value.
    private static void AddRestoreEntries(Dictionary<string, string> map, IReadOnlyList<OperatorResult> items, byte[] keyBytes)
    {
        foreach (var item in items)
        {
            if (!string.Equals(item.Operator, EncryptOperatorName, StringComparison.Ordinal))
                continue;
            if (!map.ContainsKey(item.Text))
                map[item.Text] = AesCipher.Decrypt(keyBytes, item.Text);
        }
    }

    private static AgentResponse RestoreResponse(AgentResponse response, IReadOnlyDictionary<string, string> restore)
    {
        var restored = new List<ChatMessage>(response.Messages.Count);
        var changed = false;

        foreach (var message in response.Messages)
        {
            var text = message.Text;
            if (!string.IsNullOrEmpty(text))
            {
                var newText = ApplyRestore(text, restore);
                if (!string.Equals(newText, text, StringComparison.Ordinal))
                {
                    restored.Add(GuardrailChatContent.WithText(message, newText));
                    changed = true;
                    continue;
                }
            }

            restored.Add(message);
        }

        if (!changed)
            return response;

        return new AgentResponse(restored)
        {
            ResponseId = response.ResponseId,
            AgentId = response.AgentId,
            CreatedAt = response.CreatedAt,
            Usage = response.Usage,
            FinishReason = response.FinishReason,
            AdditionalProperties = response.AdditionalProperties
        };
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
                : new AgentResponseUpdate(update.Role ?? ChatRole.Assistant, GuardrailChatContent.ReplaceText(update.Contents, newText))
                {
                    AuthorName = update.AuthorName,
                    AgentId = update.AgentId,
                    MessageId = update.MessageId,
                    ResponseId = update.ResponseId,
                    CreatedAt = update.CreatedAt,
                    FinishReason = update.FinishReason,
                    ContinuationToken = update.ContinuationToken,
                    AdditionalProperties = update.AdditionalProperties
                };
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
            MergeEntitiesWithSpaces = source.MergeEntitiesWithSpaces,
            Operators = encrypt,
        };
    }
}
