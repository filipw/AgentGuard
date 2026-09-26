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
/// encrypted (AES-GCM) into opaque tokens before the inner agent and the model provider ever see it, and
/// the tokens in the agent's response are decrypted back to the original values. The model reasons over
/// tokens, never the raw PII, while the end user still sees the real values.
/// <para>
/// This is the cross-phase round-trip the per-message guardrail rules cannot express on their own:
/// the input and output guardrail phases run on separate contexts, so a rule pair has no shared place
/// to carry the encryption tokens. This middleware keeps each request's tokens for its response, and
/// the session's tokens in the session.
/// </para>
/// </summary>
/// <remarks>
/// <para>
/// Only tokens this middleware minted for the conversation are restored: the current request's and, when the
/// run has an <see cref="AgentSession"/>, those of earlier turns of the same session, which its chat history
/// replays to the model. The session keeps them in its <see cref="AgentSession.StateBag"/> under
/// <c>AgentGuard.PiiReversibleRedaction.Tokens</c>: the ciphertext tokens only, never the values, and the most
/// recent 4,096, so they survive the session being serialized. Without a session only the current request's
/// tokens are restored; a caller that sends the whole transcript with each request has it encrypted anew each
/// time. A token from anywhere else - another session, a log, a tool result, text a user pasted - is left as it
/// is, even when it was encrypted with the same key, and so is a token the model alters.
/// </para>
/// <para>
/// A token is restored wherever it appears in the response text, including run together with other letters
/// or digits. Two runs on the same session at the same time may each overwrite the other's addition to the
/// session's tokens; the tokens of the run that lost are then not restored in later turns.
/// </para>
/// <para>
/// A streamed response is restored the same way, and reads the same as the response without streaming.
/// Text at the end of an update that could still be the start of a token is held back until that is decided,
/// which takes at most the length of a token, and then goes out, restored when it is one: with the next update
/// of its message, or in an update of its own at the end of its message, before an update carrying a
/// progressive-streaming guardrail event, or at the end of the stream. Every update keeps its non-text content
/// and metadata.
/// </para>
/// <para>
/// A separate key for each user or tenant whose data must stay apart adds defense in depth: a token minted
/// for one then can't be decrypted with another's key at all.
/// </para>
/// </remarks>
public static class PiiReversibleRedactionExtensions
{
    private const string EncryptOperatorName = "encrypt";

    /// <summary>
    /// Wraps the agent so PII in each request is encrypted before the inner agent runs, and the tokens in the
    /// response are decrypted back. See <see cref="PiiReversibleRedactionExtensions"/> for which tokens are
    /// restored; a token the model paraphrases or drops can't be.
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
                var (processed, restorer) = await ProtectAsync(engine, keyBytes, list, session, ct).ConfigureAwait(false);

                var response = await innerAgent.RunAsync(processed, session, runOptions, ct).ConfigureAwait(false);

                return restorer.Restore(response);
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
        var (processed, restorer) = await ProtectAsync(engine, keyBytes, list, session, ct).ConfigureAwait(false);

        await foreach (var update in restorer.RestoreAsync(innerAgent.RunStreamingAsync(processed, session, runOptions, ct), ct)
            .ConfigureAwait(false))
        {
            yield return update;
        }
    }

    // anonymizes PII in every text-bearing message of the request, including history a client sends
    // back and context-provider messages, records the tokens it mints in the session, and returns the
    // restorer for the response, which knows them and the session's earlier ones. Detection runs on the
    // engine's asynchronous path, which is what runs remote and Azure detectors.
    private static async Task<(IReadOnlyList<ChatMessage> Messages, PiiTokenRestorer Restorer)> ProtectAsync(
        PiiEngine engine,
        byte[] keyBytes,
        IReadOnlyList<ChatMessage> messages,
        AgentSession? session,
        CancellationToken ct)
    {
        List<ChatMessage>? rewritten = null;
        var tokens = new Dictionary<string, string>(StringComparer.Ordinal);

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
            AddTokens(tokens, deid.Items, keyBytes);
        }

        // the session's history can bring back tokens minted in its earlier turns
        var recorded = PiiTokenRegistry.Read(session);
        if (session is not null && tokens.Count > 0)
            PiiTokenRegistry.Record(session, tokens.Keys);

        return (rewritten ?? messages, new PiiTokenRestorer(keyBytes, tokens, recorded));
    }

    // maps each distinct ciphertext token back to its decrypted original value.
    private static void AddTokens(Dictionary<string, string> tokens, IReadOnlyList<OperatorResult> items, byte[] keyBytes)
    {
        foreach (var item in items)
        {
            if (!string.Equals(item.Operator, EncryptOperatorName, StringComparison.Ordinal))
                continue;
            if (!tokens.ContainsKey(item.Text))
                tokens[item.Text] = AesCipher.Decrypt(keyBytes, item.Text);
        }
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
