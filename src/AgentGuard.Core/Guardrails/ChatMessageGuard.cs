using System.Security.Cryptography;
using System.Text;
using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Ledger;
using AgentGuard.Core.Rules.ToolCall;
using AgentGuard.Core.Rules.ToolResult;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace AgentGuard.Core.Guardrails;

/// <summary>
/// Runs a policy over Microsoft.Extensions.AI chat messages: every user message on the way in, every
/// assistant message on the way out. Both adapters (the <c>IChatClient</c> decorator and the Agent
/// Framework middleware) guard conversations through it.
/// </summary>
/// <remarks>
/// <para>
/// Callers commonly send the whole conversation on every call - the usual <c>IChatClient</c> loop,
/// or a client that posts the whole transcript - so every user message is guarded on every call.
/// The newest one is always evaluated; for earlier ones the verdict already reached for
/// identical text is reused from a bounded cache, so each distinct message runs through the rules
/// once rather than once per turn. An earlier message the policy blocks is replaced with
/// <see cref="RemovedMessagePlaceholder"/>; only a block of the newest user message blocks the call.
/// </para>
/// <para>
/// On the way out each assistant message is evaluated on its own, so a redaction lands in the message
/// that contained the text and nothing is left unchecked in the earlier messages of a multi-step
/// response. The response's tool calls and results are evaluated once, together with its final text.
/// The reasoning of each assistant message (its <see cref="TextReasoningContent"/>, which
/// <see cref="ChatMessage.Text"/> leaves out) is evaluated separately: see <see cref="GuardOutputAsync"/>.
/// </para>
/// </remarks>
public sealed class ChatMessageGuard
{
    /// <summary>The text that replaces an earlier user message the policy blocks.</summary>
    public const string RemovedMessagePlaceholder = "[message removed by guardrail policy]";

    /// <summary>The default number of earlier-message verdicts kept for reuse.</summary>
    public const int DefaultVerdictCacheCapacity = 512;

    // runs the reasoning and tool-only checks: the same rules without the re-ask loop, since a
    // regenerated answer can't stand in for reasoning or for a tool call
    private readonly GuardrailPipeline _checkPipeline;
    private readonly VerdictCache _verdicts;

    /// <summary>Initializes a new instance of the <see cref="ChatMessageGuard"/> class.</summary>
    /// <param name="policy">The policy to enforce.</param>
    /// <param name="logger">Optional logger for the pipelines.</param>
    /// <param name="ledger">Optional decision ledger; every evaluation is recorded to it.</param>
    /// <param name="verdictCacheCapacity">How many earlier-message verdicts to keep for reuse.</param>
    public ChatMessageGuard(
        IGuardrailPolicy policy,
        ILogger<GuardrailPipeline>? logger = null,
        IGuardrailLedger? ledger = null,
        int verdictCacheCapacity = DefaultVerdictCacheCapacity)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(verdictCacheCapacity);

        logger ??= NullLogger<GuardrailPipeline>.Instance;

        Pipeline = new GuardrailPipeline(policy, logger, ledger);
        _checkPipeline = policy.ReaskOptions is null || policy.ReaskChatClient is null
            ? Pipeline
            : new GuardrailPipeline(new WithoutReask(policy), logger, ledger);
        _verdicts = new VerdictCache(verdictCacheCapacity);
    }

    /// <summary>
    /// The pipeline that evaluates the messages, for callers that run the policy on text of their own
    /// (it records to the same ledger).
    /// </summary>
    public GuardrailPipeline Pipeline { get; }

    /// <summary>
    /// Guards the user messages of a request. The result carries either the block or the messages to
    /// send on, with any rewrites applied.
    /// </summary>
    /// <param name="messages">The request's messages.</param>
    /// <param name="agentName">The agent the request is for, when known.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The outcome.</returns>
    public async ValueTask<ChatMessageGuardResult> GuardInputAsync(
        IReadOnlyList<ChatMessage> messages,
        string? agentName = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(messages);

        var latest = LastIndexOf(messages, IsGuardedUserMessage);
        if (latest < 0)
            return ChatMessageGuardResult.Unchanged(messages);

        // the newest user message is the input this call is about: always evaluate it
        var latestText = messages[latest].Text;
        var latestContext = CreateContext(latestText, GuardrailPhase.Input, messages, agentName);
        var latestResult = await Pipeline.RunAsync(latestContext, cancellationToken).ConfigureAwait(false);
        _verdicts.Set(latestText, Verdict.From(latestResult));

        if (latestResult.IsBlocked)
            return ChatMessageGuardResult.Blocked(messages, latestResult.BlockingResult!, latestContext);

        List<ChatMessage>? rewritten = null;

        if (latestResult.WasModified)
            (rewritten ??= [.. messages])[latest] = GuardrailChatContent.WithText(messages[latest], latestResult.FinalText);

        // earlier user messages get the treatment they got when they were the newest
        for (var i = 0; i < latest; i++)
        {
            var message = messages[i];
            if (!IsGuardedUserMessage(message))
                continue;

            var verdict = await GetVerdictAsync(messages, i, agentName, cancellationToken).ConfigureAwait(false);

            if (verdict.IsBlocked)
            {
                // attachments go too: they belonged to a turn the policy rejected
                (rewritten ??= [.. messages])[i] = new ChatMessage(message.Role, RemovedMessagePlaceholder)
                {
                    AuthorName = message.AuthorName,
                    MessageId = message.MessageId,
                    CreatedAt = message.CreatedAt
                };
            }
            else if (verdict.ModifiedText is { } modifiedText)
            {
                (rewritten ??= [.. messages])[i] = GuardrailChatContent.WithText(message, modifiedText);
            }
        }

        return rewritten is null
            ? ChatMessageGuardResult.Unchanged(messages)
            : ChatMessageGuardResult.Modified(rewritten);
    }

    /// <summary>
    /// Guards the messages of a response. The result carries either the block or the response
    /// messages, with any rewrites applied.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The text of each assistant message is evaluated on its own, and the response's tool calls and
    /// results together with its final text; without re-ask on their own when there is no such text to
    /// evaluate them with. A block of any of these blocks the response. A successful re-ask replaces all
    /// of the response's text (see <see cref="GuardrailChatContent.ReplaceAnswer"/>), and the reasoning
    /// text of the messages it replaced goes with it.
    /// </para>
    /// <para>
    /// Then the reasoning text of each assistant message is evaluated as an Output-phase run of its
    /// own, without re-ask. A rewrite replaces the reasoning text and a block removes it; neither
    /// affects the answer. Encrypted reasoning (<see cref="TextReasoningContent.ProtectedData"/>) and
    /// every other content are kept, and a message left with no content is dropped.
    /// </para>
    /// </remarks>
    /// <param name="responseMessages">The response's messages.</param>
    /// <param name="requestMessages">
    /// The request that produced the response. Each evaluation gets it as conversation history, followed by
    /// the response's messages before the one evaluated (tool calls and results included).
    /// </param>
    /// <param name="agentName">The agent that responded, when known.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The outcome.</returns>
    public ValueTask<ChatMessageGuardResult> GuardOutputAsync(
        IReadOnlyList<ChatMessage> responseMessages,
        IReadOnlyList<ChatMessage>? requestMessages = null,
        string? agentName = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(responseMessages);

        return GuardOutputCoreAsync(responseMessages, requestMessages, agentName, guardText: true, cancellationToken);
    }

    /// <summary>
    /// Guards everything in a response except its text: the tool calls and results, evaluated together
    /// without re-ask, and the reasoning of each assistant message, as in <see cref="GuardOutputAsync"/>.
    /// The text is left as it is.
    /// </summary>
    /// <remarks>
    /// For progressive streaming, where the text has already been checked chunk by chunk and the rest
    /// of the response was held back until the stream ended.
    /// </remarks>
    /// <param name="responseMessages">The response's messages.</param>
    /// <param name="requestMessages">
    /// The request that produced the response. Each evaluation gets it as conversation history, followed by
    /// the response's messages before the one evaluated (tool calls and results included).
    /// </param>
    /// <param name="agentName">The agent that responded, when known.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The outcome.</returns>
    public ValueTask<ChatMessageGuardResult> GuardToolsAndReasoningAsync(
        IReadOnlyList<ChatMessage> responseMessages,
        IReadOnlyList<ChatMessage>? requestMessages = null,
        string? agentName = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(responseMessages);

        return GuardOutputCoreAsync(responseMessages, requestMessages, agentName, guardText: false, cancellationToken);
    }

    private async ValueTask<ChatMessageGuardResult> GuardOutputCoreAsync(
        IReadOnlyList<ChatMessage> responseMessages,
        IReadOnlyList<ChatMessage>? requestMessages,
        string? agentName,
        bool guardText,
        CancellationToken cancellationToken)
    {
        var contents = responseMessages.SelectMany(m => m.Contents).ToList();
        var toolCalls = GuardrailChatContent.ExtractToolCalls(contents);
        var toolResults = GuardrailChatContent.ExtractToolResults(contents);

        var textIndexes = new List<int>();
        if (guardText)
        {
            for (var i = 0; i < responseMessages.Count; i++)
            {
                if (responseMessages[i].Role == ChatRole.Assistant && !string.IsNullOrEmpty(responseMessages[i].Text))
                    textIndexes.Add(i);
            }
        }

        IReadOnlyList<ChatMessage>? rewritten = null;
        var toolsChecked = false;

        if (textIndexes.Count > 0)
        {
            List<ChatMessage>? withText = null;

            for (var n = 0; n < textIndexes.Count; n++)
            {
                var index = textIndexes[n];
                var context = CreateContext(
                    responseMessages[index].Text,
                    GuardrailPhase.Output,
                    HistoryBefore(requestMessages, (IReadOnlyList<ChatMessage>?)withText ?? responseMessages, index),
                    agentName);

                // tool calls and results belong to the response as a whole: evaluate them once, with its final text
                var withTools = n == textIndexes.Count - 1;
                if (withTools)
                    AddToolProperties(context, toolCalls, toolResults);

                var result = await Pipeline.RunAsync(context, cancellationToken).ConfigureAwait(false);

                if (result.IsBlocked)
                    return ChatMessageGuardResult.Blocked(responseMessages, result.BlockingResult!, context);

                toolsChecked = withTools;

                if (result.WasReasked && result.WasModified)
                {
                    // a re-ask regenerated the whole answer, so it replaces all of the response's text,
                    // and the reasoning behind the old answer goes with it
                    rewritten = GuardrailChatContent.ReplaceAnswer(
                        [.. responseMessages.Select((m, i) => textIndexes.Contains(i) ? WithoutReasoningText(m) : m)],
                        result.FinalText);
                    break;
                }

                if (result.WasModified)
                    (withText ??= [.. responseMessages])[index] = GuardrailChatContent.WithText(responseMessages[index], result.FinalText);
            }

            rewritten ??= withText;
        }

        // a response without text to evaluate them with, or one whose answer a re-ask replaced before
        // its final text was reached, still has its tool calls and results checked
        if (!toolsChecked && (toolCalls.Count > 0 || toolResults.Count > 0))
        {
            var current = rewritten ?? responseMessages;
            var toolContext = CreateContext("", GuardrailPhase.Output, HistoryBefore(requestMessages, current, current.Count), agentName);
            AddToolProperties(toolContext, toolCalls, toolResults);

            var toolResult = await _checkPipeline.RunAsync(toolContext, cancellationToken).ConfigureAwait(false);
            if (toolResult.IsBlocked)
                return ChatMessageGuardResult.Blocked(responseMessages, toolResult.BlockingResult!, toolContext);
        }

        var guarded = await GuardReasoningAsync(rewritten ?? responseMessages, requestMessages, agentName, cancellationToken)
            .ConfigureAwait(false);

        return guarded is null && rewritten is null
            ? ChatMessageGuardResult.Unchanged(responseMessages)
            : ChatMessageGuardResult.Modified(guarded ?? rewritten!);
    }

    // returns the messages with their reasoning guarded, or null when no reasoning changed
    private async ValueTask<List<ChatMessage>?> GuardReasoningAsync(
        IReadOnlyList<ChatMessage> messages,
        IReadOnlyList<ChatMessage>? requestMessages,
        string? agentName,
        CancellationToken cancellationToken)
    {
        List<ChatMessage>? guarded = null;

        for (var i = 0; i < messages.Count; i++)
        {
            var message = messages[i];
            var reasoning = message.Role == ChatRole.Assistant ? GuardrailChatContent.GetReasoningText(message.Contents) : "";

            ChatMessage? replacement = message;
            if (!string.IsNullOrWhiteSpace(reasoning))
            {
                var result = await _checkPipeline.RunAsync(
                    CreateContext(reasoning, GuardrailPhase.Output, HistoryBefore(requestMessages, messages, i), agentName),
                    cancellationToken).ConfigureAwait(false);

                // a block removes the reasoning text but leaves the answer alone
                if (result.IsBlocked)
                    replacement = WithoutReasoningText(message);
                else if (result.WasModified)
                    replacement = GuardrailChatContent.WithReasoningText(message, result.FinalText);

                if (replacement.Contents.Count == 0)
                    replacement = null;
            }

            if (!ReferenceEquals(replacement, message))
                guarded ??= [.. messages.Take(i)];

            if (guarded is not null && replacement is not null)
                guarded.Add(replacement);
        }

        return guarded;
    }

    // the conversation as it stood when the response message at index was written: the request, then the
    // response's earlier messages as the rules have left them, so a judge sees the tool calls and results
    // the answer was built on
    private static IReadOnlyList<ChatMessage>? HistoryBefore(
        IReadOnlyList<ChatMessage>? requestMessages, IReadOnlyList<ChatMessage> responseMessages, int index)
    {
        if (index == 0)
            return requestMessages;

        var history = new List<ChatMessage>((requestMessages?.Count ?? 0) + index);
        if (requestMessages is not null)
            history.AddRange(requestMessages);

        for (var i = 0; i < index; i++)
            history.Add(responseMessages[i]);

        return history;
    }

    private async ValueTask<Verdict> GetVerdictAsync(
        IReadOnlyList<ChatMessage> messages, int index, string? agentName, CancellationToken cancellationToken)
    {
        var text = messages[index].Text;
        if (_verdicts.TryGet(text, out var cached))
            return cached;

        // evaluate it against the conversation as it stood when it was the newest message
        var history = messages.Take(index + 1).ToList();
        var result = await Pipeline.RunAsync(
            CreateContext(text, GuardrailPhase.Input, history, agentName), cancellationToken).ConfigureAwait(false);

        var verdict = Verdict.From(result);
        _verdicts.Set(text, verdict);
        return verdict;
    }

    private static ChatMessage WithoutReasoningText(ChatMessage message) =>
        GuardrailChatContent.GetReasoningText(message.Contents).Length == 0
            ? message
            : GuardrailChatContent.WithReasoningText(message, "");

    private static void AddToolProperties(
        GuardrailContext context, List<AgentToolCall> toolCalls, List<ToolResultEntry> toolResults)
    {
        if (toolCalls.Count > 0)
            context.Properties[ToolCallGuardrailRule.ToolCallsKey] = (IReadOnlyList<AgentToolCall>)toolCalls;

        if (toolResults.Count > 0)
            context.Properties[ToolResultGuardrailRule.ToolResultsKey] = (IReadOnlyList<ToolResultEntry>)toolResults;
    }

    private static GuardrailContext CreateContext(
        string text, GuardrailPhase phase, IReadOnlyList<ChatMessage>? messages, string? agentName) => new()
        {
            Text = text,
            Phase = phase,
            Messages = messages,
            AgentName = agentName
        };

    private static bool IsGuardedUserMessage(ChatMessage message) =>
        message.Role == ChatRole.User && !string.IsNullOrWhiteSpace(message.Text);

    private static int LastIndexOf(IReadOnlyList<ChatMessage> messages, Func<ChatMessage, bool> predicate)
    {
        for (var i = messages.Count - 1; i >= 0; i--)
        {
            if (predicate(messages[i]))
                return i;
        }

        return -1;
    }

    private readonly record struct Verdict(bool IsBlocked, string? ModifiedText)
    {
        public static Verdict From(GuardrailPipelineResult result) =>
            new(result.IsBlocked, !result.IsBlocked && result.WasModified ? result.FinalText : null);
    }

    // bounded, first-in-first-out; keyed by a hash so long messages don't pin their text in memory twice
    private sealed class VerdictCache(int capacity)
    {
        private readonly Dictionary<string, Verdict> _entries = new(StringComparer.Ordinal);
        private readonly Queue<string> _order = new();
        private readonly Lock _lock = new();

        public bool TryGet(string text, out Verdict verdict)
        {
            var key = KeyOf(text);
            lock (_lock)
            {
                return _entries.TryGetValue(key, out verdict);
            }
        }

        public void Set(string text, Verdict verdict)
        {
            var key = KeyOf(text);
            lock (_lock)
            {
                if (!_entries.ContainsKey(key))
                {
                    _order.Enqueue(key);
                    if (_order.Count > capacity)
                        _entries.Remove(_order.Dequeue());
                }

                _entries[key] = verdict;
            }
        }

        private static string KeyOf(string text) =>
            Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text)));
    }

    // the policy's rules and violation handler, without the re-ask loop
    private sealed class WithoutReask(IGuardrailPolicy policy) : IGuardrailPolicy
    {
        public string Name => policy.Name;

        public IReadOnlyList<IGuardrailRule> Rules => policy.Rules;

        public IViolationHandler ViolationHandler => policy.ViolationHandler;
    }
}

/// <summary>The outcome of guarding a set of chat messages with a <see cref="ChatMessageGuard"/>.</summary>
public sealed record ChatMessageGuardResult
{
    /// <summary>The messages to continue with: the originals, or copies with the policy's rewrites applied.</summary>
    public required IReadOnlyList<ChatMessage> Messages { get; init; }

    /// <summary>Whether the policy blocked the messages.</summary>
    public bool IsBlocked { get; init; }

    /// <summary>Whether <see cref="Messages"/> differs from what went in.</summary>
    public bool WasModified { get; init; }

    /// <summary>The rule result that blocked, when <see cref="IsBlocked"/> is true.</summary>
    public GuardrailResult? BlockingResult { get; init; }

    /// <summary>The context the block happened in - what a violation handler should be given.</summary>
    public GuardrailContext? BlockingContext { get; init; }

    internal static ChatMessageGuardResult Unchanged(IReadOnlyList<ChatMessage> messages) =>
        new() { Messages = messages };

    internal static ChatMessageGuardResult Modified(IReadOnlyList<ChatMessage> messages) =>
        new() { Messages = messages, WasModified = true };

    internal static ChatMessageGuardResult Blocked(
        IReadOnlyList<ChatMessage> messages, GuardrailResult blockingResult, GuardrailContext context) =>
        new() { Messages = messages, IsBlocked = true, BlockingResult = blockingResult, BlockingContext = context };
}
