using System.Security.Cryptography;
using System.Text;
using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Rules.ToolCall;
using AgentGuard.Core.Rules.ToolResult;
using Microsoft.Extensions.AI;

namespace AgentGuard.Core.Guardrails;

/// <summary>
/// Runs a <see cref="GuardrailPipeline"/> over Microsoft.Extensions.AI chat messages: every user
/// message on the way in, every assistant message on the way out. Both adapters (the
/// <c>IChatClient</c> decorator and the Agent Framework middleware) guard conversations through it.
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
/// </para>
/// </remarks>
public sealed class ChatMessageGuard
{
    /// <summary>The text that replaces an earlier user message the policy blocks.</summary>
    public const string RemovedMessagePlaceholder = "[message removed by guardrail policy]";

    /// <summary>The default number of earlier-message verdicts kept for reuse.</summary>
    public const int DefaultVerdictCacheCapacity = 512;

    private readonly GuardrailPipeline _pipeline;
    private readonly VerdictCache _verdicts;

    /// <summary>Initializes a new instance of the <see cref="ChatMessageGuard"/> class.</summary>
    /// <param name="pipeline">The pipeline to run.</param>
    /// <param name="verdictCacheCapacity">How many earlier-message verdicts to keep for reuse.</param>
    public ChatMessageGuard(GuardrailPipeline pipeline, int verdictCacheCapacity = DefaultVerdictCacheCapacity)
    {
        ArgumentNullException.ThrowIfNull(pipeline);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(verdictCacheCapacity);

        _pipeline = pipeline;
        _verdicts = new VerdictCache(verdictCacheCapacity);
    }

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
        var latestResult = await _pipeline.RunAsync(latestContext, cancellationToken).ConfigureAwait(false);
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
    /// <param name="responseMessages">The response's messages.</param>
    /// <param name="requestMessages">The request that produced the response, used as conversation context.</param>
    /// <param name="agentName">The agent that responded, when known.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The outcome.</returns>
    public async ValueTask<ChatMessageGuardResult> GuardOutputAsync(
        IReadOnlyList<ChatMessage> responseMessages,
        IReadOnlyList<ChatMessage>? requestMessages = null,
        string? agentName = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(responseMessages);

        var contents = responseMessages.SelectMany(m => m.Contents).ToList();
        var toolCalls = GuardrailChatContent.ExtractToolCalls(contents);
        var toolResults = GuardrailChatContent.ExtractToolResults(contents);

        var textIndexes = new List<int>();
        for (var i = 0; i < responseMessages.Count; i++)
        {
            if (responseMessages[i].Role == ChatRole.Assistant && !string.IsNullOrEmpty(responseMessages[i].Text))
                textIndexes.Add(i);
        }

        if (textIndexes.Count == 0)
        {
            if (toolCalls.Count == 0 && toolResults.Count == 0)
                return ChatMessageGuardResult.Unchanged(responseMessages);

            var toolContext = CreateContext("", GuardrailPhase.Output, requestMessages, agentName);
            AddToolProperties(toolContext, toolCalls, toolResults);

            var toolResult = await _pipeline.RunAsync(toolContext, cancellationToken).ConfigureAwait(false);
            return toolResult.IsBlocked
                ? ChatMessageGuardResult.Blocked(responseMessages, toolResult.BlockingResult!, toolContext)
                : ChatMessageGuardResult.Unchanged(responseMessages);
        }

        List<ChatMessage>? rewritten = null;

        for (var n = 0; n < textIndexes.Count; n++)
        {
            var index = textIndexes[n];
            var context = CreateContext(responseMessages[index].Text, GuardrailPhase.Output, requestMessages, agentName);

            // tool calls and results belong to the response as a whole: evaluate them once, with its final text
            if (n == textIndexes.Count - 1)
                AddToolProperties(context, toolCalls, toolResults);

            var result = await _pipeline.RunAsync(context, cancellationToken).ConfigureAwait(false);

            if (result.IsBlocked)
                return ChatMessageGuardResult.Blocked(responseMessages, result.BlockingResult!, context);

            if (result.WasReasked && result.WasModified)
            {
                // a re-ask regenerated the whole answer, so it replaces all of the response's text
                return ChatMessageGuardResult.Modified(ReplaceAnswer(responseMessages, textIndexes, result.FinalText));
            }

            if (result.WasModified)
                (rewritten ??= [.. responseMessages])[index] = GuardrailChatContent.WithText(responseMessages[index], result.FinalText);
        }

        return rewritten is null
            ? ChatMessageGuardResult.Unchanged(responseMessages)
            : ChatMessageGuardResult.Modified(rewritten);
    }

    private async ValueTask<Verdict> GetVerdictAsync(
        IReadOnlyList<ChatMessage> messages, int index, string? agentName, CancellationToken cancellationToken)
    {
        var text = messages[index].Text;
        if (_verdicts.TryGet(text, out var cached))
            return cached;

        // evaluate it against the conversation as it stood when it was the newest message
        var history = messages.Take(index + 1).ToList();
        var result = await _pipeline.RunAsync(
            CreateContext(text, GuardrailPhase.Input, history, agentName), cancellationToken).ConfigureAwait(false);

        var verdict = Verdict.From(result);
        _verdicts.Set(text, verdict);
        return verdict;
    }

    private static List<ChatMessage> ReplaceAnswer(IReadOnlyList<ChatMessage> messages, List<int> textIndexes, string answer)
    {
        var last = textIndexes[^1];
        var result = new List<ChatMessage>(messages.Count);

        for (var i = 0; i < messages.Count; i++)
        {
            if (!textIndexes.Contains(i))
            {
                result.Add(messages[i]);
                continue;
            }

            var rewritten = GuardrailChatContent.WithText(messages[i], i == last ? answer : "");
            if (rewritten.Contents.Count > 0)
                result.Add(rewritten);
        }

        return result;
    }

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
