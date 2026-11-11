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
/// <para>
/// The tools the agent invokes are part of the round-trip: a tool is called with the original values of the
/// tokens in its arguments, and the PII in what it returns is encrypted before the model sees it.
/// </para>
/// </summary>
/// <remarks>
/// <para>
/// Only tokens this middleware minted for the conversation are restored: the current request's, those of the
/// run's tool results and, when the run has an <see cref="AgentSession"/>, those of earlier turns of the same
/// session, which its chat history replays to the model. The session keeps them in its
/// <see cref="AgentSession.StateBag"/> under <c>AgentGuard.PiiReversibleRedaction.Tokens</c>: the ciphertext
/// tokens only, never the values, and the most recent 4,096, so they survive the session being serialized.
/// Without a session only the current run's tokens are restored; a caller that sends the whole transcript with
/// each request has it encrypted anew each time. A token from anywhere else - another session, a log, text a
/// user pasted or a tool returned - is left as it is, even when it was encrypted with the same key, and so is a
/// token the model alters.
/// </para>
/// <para>
/// A token is restored wherever it appears in the response's text and in its reasoning text
/// (<see cref="TextReasoningContent"/>), including run together with other letters or digits. The tool calls
/// and tool results the response carries are left as the model saw them, with their tokens.
/// </para>
/// <para>
/// A streamed response is restored the same way, and reads the same as the response without streaming.
/// Text at the end of an update that could still be the start of a token is held back until that is decided,
/// which takes at most the length of a token, and then goes out, restored when it is one: with the next update
/// of its message, or in an update of its own at the end of its message, before an update carrying a
/// progressive-streaming guardrail event, or at the end of the stream. Reasoning text is held the same way, and
/// no longer than the first update that brings answer text. Every update keeps its other content and metadata.
/// </para>
/// <para>
/// Tools. When the agent invokes its functions itself - it has a <see cref="FunctionInvokingChatClient"/> in
/// its pipeline, as a <c>ChatClientAgent</c> does - a function-invocation middleware is wired with this one.
/// Before a tool runs, the tokens in its arguments are replaced by their original values: in strings at any
/// depth of a JSON value, a dictionary or a list, but not in property names or inside other objects. The tool
/// is the caller's own code and needs the real value; the call the model made keeps its tokens, in the response
/// and in the session's history. What the tool returns is encrypted like a request message before the model
/// sees it, and the tokens minted there are restored in the answer, in the arguments of later calls, and in
/// later turns of the session. A string result stays a string. Any other result is scanned as the JSON text the
/// model would be sent, property names included, and goes on as JSON when PII was found in it - or as that text
/// when encrypting left it invalid JSON, as when a token takes the place of a number. In a result made of
/// content items the text items are encrypted, and images and other data go on as they are. Tools that run
/// concurrently are supported.
/// </para>
/// <para>
/// Not covered, because no function-invocation middleware sees them: tools the service runs (hosted tools),
/// and calls the agent hands back for the caller to run or approve - their arguments reach the caller as
/// tokens, and a result the caller sends back is not encrypted. The message of an exception a tool throws is
/// not encrypted either; the model sees it only when the function-invoking client includes detailed errors.
/// The function-invocation middleware accepts run options of type <see cref="AgentRunOptions"/> or
/// <c>ChatClientAgentRunOptions</c> only: a run of such an agent with another options type fails with a
/// <see cref="NotSupportedException"/> instead of running its tools unprotected.
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
    /// <remarks>
    /// The functions the agent invokes through a <see cref="FunctionInvokingChatClient"/> are called with the
    /// original values of the tokens in their arguments, and their results are encrypted before the model sees
    /// them. Hosted tools, calls handed back to the caller, the tool calls and results carried in the response,
    /// and run options other than <see cref="AgentRunOptions"/> or <c>ChatClientAgentRunOptions</c> are the
    /// limits: see the remarks of <see cref="PiiReversibleRedactionExtensions"/>.
    /// </remarks>
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
    /// <para>
    /// Use this when the engine holds resources - a remote detector's <see cref="System.Net.Http.HttpClient"/>,
    /// an ONNX NER session - or when one engine should be shared across several agents. The engine
    /// is never disposed here; its lifetime stays with whoever built it. Detection runs on the engine's
    /// asynchronous path, so remote and Azure detectors take part. Configure it with the reversible
    /// <c>encrypt</c> operator, which <see cref="UsePiiReversibleRedaction(AIAgentBuilder, string, PiiOptions?)"/>
    /// does for you: spans anonymized by any other operator still never reach the model, but they can't
    /// be restored in the response, nor in the arguments of a tool call.
    /// </para>
    /// <para>
    /// The functions the agent invokes through a <see cref="FunctionInvokingChatClient"/> are called with the
    /// original values of the tokens in their arguments, and their results are encrypted with the same engine
    /// before the model sees them - concurrently when tools run concurrently, so the engine has to allow that.
    /// Hosted tools, calls handed back to the caller, the tool calls and results carried in the response, and
    /// run options other than <see cref="AgentRunOptions"/> or <c>ChatClientAgentRunOptions</c> are the limits:
    /// see the remarks of <see cref="PiiReversibleRedactionExtensions"/>.
    /// </para>
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

        var tools = new PiiToolRedaction(engine, keyBytes);

        return builder.Use((innerAgent, services) =>
        {
            var pipeline = new AIAgentBuilder(innerAgent);

            pipeline.Use(
                runFunc: async (messages, session, runOptions, agent, ct) =>
                {
                    var list = messages as IReadOnlyList<ChatMessage> ?? messages.ToList();
                    var (processed, restorer) = await ProtectAsync(engine, keyBytes, list, session, ct).ConfigureAwait(false);

                    tools.Begin(restorer, session);
                    var response = await agent.RunAsync(processed, session, runOptions, ct).ConfigureAwait(false);

                    return restorer.Restore(response);
                },
                runStreamingFunc: (messages, session, runOptions, agent, ct) =>
                    ProtectAndStreamAsync(engine, keyBytes, tools, messages, session, runOptions, agent, ct));

            // only an agent that invokes functions itself has tool calls to intercept, and the function
            // middleware fails the run of one that does not
            if (innerAgent.GetService<FunctionInvokingChatClient>() is not null)
                pipeline.Use(tools.InvokeAsync);

            return pipeline.Build(services);
        });
    }

    private static async IAsyncEnumerable<AgentResponseUpdate> ProtectAndStreamAsync(
        PiiEngine engine,
        byte[] keyBytes,
        PiiToolRedaction tools,
        IEnumerable<ChatMessage> messages,
        AgentSession? session,
        AgentRunOptions? runOptions,
        AIAgent innerAgent,
        [EnumeratorCancellation] CancellationToken ct)
    {
        var list = messages as IReadOnlyList<ChatMessage> ?? messages.ToList();
        var (processed, restorer) = await ProtectAsync(engine, keyBytes, list, session, ct).ConfigureAwait(false);

        var updates = tools.StreamAsync(restorer, session, innerAgent.RunStreamingAsync(processed, session, runOptions, ct), ct);

        await foreach (var update in restorer.RestoreAsync(updates, ct).ConfigureAwait(false))
            yield return update;
    }

    // anonymizes PII in every text-bearing message of the request, including history a client sends
    // back and context-provider messages, records the tokens it mints in the session, and returns the
    // restorer for the run, which knows them and the session's earlier ones. Detection runs on the
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
    internal static void AddTokens(Dictionary<string, string> tokens, IReadOnlyList<OperatorResult> items, byte[] keyBytes)
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
