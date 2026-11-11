using System.Security.Cryptography;
using System.Text;
using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Ledger;
using AgentGuard.Core.Rules;
using AgentGuard.Core.Rules.ToolCall;
using AgentGuard.Core.Rules.ToolResult;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace AgentGuard.Core.Guardrails;

/// <summary>
/// Runs a policy over Microsoft.Extensions.AI chat messages: every request message (whatever its role,
/// unless the host trusts it) and every tool result in the request on the way in, every assistant
/// message on the way out. Both adapters (the <c>IChatClient</c> decorator and the Agent
/// Framework middleware) guard conversations through it.
/// </summary>
/// <remarks>
/// <para>
/// Callers commonly send the whole conversation on every call - the usual <c>IChatClient</c> loop,
/// or a client that posts the whole transcript - so every message is guarded on every call.
/// The newest user message is always evaluated; for the others the verdict already reached for
/// identical text is reused from a bounded cache, so each distinct message runs through the rules
/// once rather than once per turn. Any other message the policy blocks is replaced with
/// <see cref="RemovedMessagePlaceholder"/>; only a block of the newest user message blocks the call.
/// </para>
/// <para>
/// An assistant message in a request is not judged by the input rules when its text is one this guard
/// released as a response: that is the model's own earlier answer, which already went through the output
/// rules. The guard remembers released answers in the same bounded cache, so after a restart, on another
/// instance, or once the cache has moved on, the message is judged like any other.
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

    /// <summary>The text that replaces a tool result in a request that the policy blocks.</summary>
    public const string BlockedToolResultPlaceholder = "[blocked: tool result violated guardrail policy]";

    /// <summary>
    /// The <see cref="GuardrailContext.Properties"/> key present (with the value <c>true</c>) when the
    /// output rules run for a response's tool calls and results alone: the response has no answer text,
    /// and <see cref="GuardrailContext.Text"/> is empty. A rule that judges the answer - "the output
    /// must contain a disclaimer" - has nothing to judge then and should pass.
    /// </summary>
    public const string ToolContentOnlyKey = "AgentGuard.ToolContentOnly";

    /// <summary>The default number of earlier-message verdicts kept for reuse.</summary>
    public const int DefaultVerdictCacheCapacity = 512;

    // runs the reasoning and tool-only checks: the same rules without the re-ask loop, since a
    // regenerated answer can't stand in for reasoning or for a tool call
    private readonly GuardrailPipeline _checkPipeline;
    private readonly VerdictCache _verdicts;

    // whether a verdict reached for a text may be reused for the same text later. Not when a rule is
    // gated with When()/Unless(): what it decides depends on who is asking, not only on the text.
    private readonly bool _reuseVerdicts;

    // checks the tool results a request carries; null when the policy has no tool-result rule
    private readonly ToolRulePipelines? _requestTools;

    // roles whose request messages the host vouches for, and which input rules therefore skip
    private readonly IReadOnlySet<ChatRole> _trustedRoles = new HashSet<ChatRole>();

    // where the host runs this guard (see GuardrailContext.Stage); null for a guard made by the constructor
    private readonly string? _stage;

    // whether a response's tool calls and results are evaluated; a host that checks them where they
    // happen turns this off
    private readonly bool _guardToolContent = true;

    // picks out the request messages the host added itself (see WithSupplementalMessages); null when
    // every user message is the caller's
    private readonly Func<ChatMessage, bool>? _isSupplemental;

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
        _reuseVerdicts = !policy.Rules.Any(rule => rule is ConditionalGuardrailRule);

        var tools = ToolRulePipelines.Create(policy, ToolRulePipelines.DefaultResultRuleOrders, logger, ledger);
        _requestTools = tools.ChecksResults ? tools : null;
    }

    // a view over an existing guard: same pipelines and verdict cache, its own stage, tool setting,
    // trusted roles and supplemental-message test
    private ChatMessageGuard(
        ChatMessageGuard source,
        string? stage,
        bool guardToolContent,
        IReadOnlySet<ChatRole> trustedRoles,
        Func<ChatMessage, bool>? isSupplemental = null)
    {
        _isSupplemental = isSupplemental ?? source._isSupplemental;
        Pipeline = source.Pipeline;
        _checkPipeline = source._checkPipeline;
        _verdicts = source._verdicts;
        _reuseVerdicts = source._reuseVerdicts;
        _requestTools = source._requestTools;
        _stage = stage;
        _guardToolContent = guardToolContent;
        _trustedRoles = trustedRoles;
    }

    /// <summary>
    /// The pipeline that evaluates the messages, for callers that run the policy on text of their own
    /// (it records to the same ledger).
    /// </summary>
    public GuardrailPipeline Pipeline { get; }

    /// <summary>
    /// Returns a guard that shares this guard's pipelines and verdict cache but marks every evaluation
    /// with <paramref name="stage"/> (see <see cref="GuardrailContext.Stage"/>), so ledger decisions
    /// record where in the host they were made.
    /// </summary>
    /// <param name="stage">Where the host runs the returned guard, for example <c>input</c>.</param>
    /// <returns>The guard.</returns>
    public ChatMessageGuard WithStage(string stage)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(stage);
        return new ChatMessageGuard(this, stage, _guardToolContent, _trustedRoles);
    }

    /// <summary>
    /// Returns a guard that shares this guard's pipelines and verdict cache but leaves out the tool calls
    /// and tool results in a response, for hosts that check them where they happen - each call before it
    /// runs, each result before it reaches the model.
    /// </summary>
    /// <returns>The guard.</returns>
    public ChatMessageGuard WithoutToolContent() => new(this, _stage, guardToolContent: false, _trustedRoles);

    /// <summary>
    /// Returns a guard that shares this guard's pipelines and verdict cache but leaves the request
    /// messages of <paramref name="roles"/> unchecked in <see cref="GuardInputAsync"/>: their text and
    /// the tool results they carry.
    /// </summary>
    /// <remarks>
    /// By default every message of a request is checked, whatever its role, because a caller that
    /// sends a transcript can write any role it likes. Trust a role only when the host, not the caller,
    /// authors every message with it - for example <see cref="ChatRole.System"/> when the system prompt
    /// is the application's own and callers cannot add system messages. The user role cannot be trusted.
    /// A checked system prompt is judged like user input: its instructions can read as an injection, its
    /// contact details as PII and its length against an input token limit, and a block replaces it with
    /// <see cref="RemovedMessagePlaceholder"/>.
    /// </remarks>
    /// <param name="roles">The roles to trust.</param>
    /// <returns>The guard.</returns>
    public ChatMessageGuard WithTrustedRoles(params IEnumerable<ChatRole> roles)
    {
        ArgumentNullException.ThrowIfNull(roles);

        var trusted = roles.ToHashSet();
        if (trusted.Contains(ChatRole.User))
            throw new ArgumentException("The user role cannot be trusted: user messages are the input being guarded.", nameof(roles));

        return new ChatMessageGuard(this, _stage, _guardToolContent, trusted);
    }

    /// <summary>
    /// Returns a guard that shares this guard's pipelines and verdict cache but does not take the
    /// messages <paramref name="isSupplemental"/> selects for the input a request is about.
    /// </summary>
    /// <remarks>
    /// <see cref="GuardInputAsync"/> blocks the call when the newest user message is blocked and only
    /// replaces any other message. A host that adds user-role messages of its own to a request -
    /// retrieved reference material, memories - after the caller's question would otherwise make its
    /// addition "the newest user message", and an injection in the caller's question would be replaced
    /// rather than block the call. Supplemental messages are still judged like every other message.
    /// </remarks>
    /// <param name="isSupplemental">Returns true for a message the host added to the request itself.</param>
    /// <returns>The guard.</returns>
    public ChatMessageGuard WithSupplementalMessages(Func<ChatMessage, bool> isSupplemental)
    {
        ArgumentNullException.ThrowIfNull(isSupplemental);
        return new ChatMessageGuard(this, _stage, _guardToolContent, _trustedRoles, isSupplemental);
    }

    /// <summary>
    /// Guards the messages of a request. The result carries either the block or the messages to send
    /// on, with any rewrites applied.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The newest user message is evaluated, and a block of it blocks the call. Every other message
    /// with text, whatever its role, is judged too (with the verdict cache), since a caller that posts
    /// a transcript can put anything in an assistant, system or tool message; one the policy blocks is
    /// replaced with <see cref="RemovedMessagePlaceholder"/>. See <see cref="WithTrustedRoles"/> to leave
    /// out roles only the host writes.
    /// </para>
    /// <para>
    /// When the policy has a tool-result rule, each <see cref="FunctionResultContent"/> in the request is
    /// also checked the way the Agent Framework tool middleware checks a result before the model sees
    /// it: the output PII and secrets rules rewrite it, then the tool-result rule inspects it. A blocked
    /// result is replaced with <see cref="BlockedToolResultPlaceholder"/> and a sanitized one is
    /// substituted. This is what lets an <c>IChatClient</c> decorator placed inside a
    /// <c>FunctionInvokingChatClient</c> guard tool results before the model reads them.
    /// </para>
    /// </remarks>
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

        List<ChatMessage>? rewritten = null;

        var latest = LastIndexOf(messages, IsCallerInput);

        // a request made up of supplemental messages alone still has an input: its newest user message
        if (latest < 0 && _isSupplemental is not null)
            latest = LastIndexOf(messages, IsGuardedUserMessage);

        if (latest >= 0)
        {
            // the newest user message is the input this call is about: always evaluate it
            var latestText = messages[latest].Text;
            var latestContext = CreateContext(latestText, GuardrailPhase.Input, messages, agentName);
            var latestResult = await Pipeline.RunAsync(latestContext, cancellationToken).ConfigureAwait(false);
            Remember(latestText, latestResult);

            if (latestResult.IsBlocked)
                return ChatMessageGuardResult.Blocked(messages, latestResult.BlockingResult!, latestContext);

            if (latestResult.WasModified)
                (rewritten ??= [.. messages])[latest] = GuardrailChatContent.WithText(messages[latest], latestResult.FinalText);
        }

        // every other message the caller sent, whatever its role, gets the treatment it got when it was
        // first seen: a caller that posts a transcript can put anything in an assistant, system or tool
        // message, and all of it reaches the model
        for (var i = 0; i < messages.Count; i++)
        {
            var message = messages[i];
            if (i == latest || !IsGuardedInputMessage(message))
                continue;

            var verdict = await GetVerdictAsync(messages, i, agentName, cancellationToken).ConfigureAwait(false);

            if (verdict.IsBlocked)
            {
                (rewritten ??= [.. messages])[i] = Removed(message);
            }
            else if (verdict.ModifiedText is { } modifiedText)
            {
                (rewritten ??= [.. messages])[i] = GuardrailChatContent.WithText(message, modifiedText);
            }
        }

        // the tool results the request carries go through the policy's tool-result rules before the
        // model reads them: inside a FunctionInvokingChatClient this is the only place they pass through,
        // and in a client-supplied transcript they are whatever the client wrote
        if (await GuardRequestToolResultsAsync((IReadOnlyList<ChatMessage>?)rewritten ?? messages, agentName, cancellationToken)
                .ConfigureAwait(false) is { } withResults)
        {
            rewritten = withResults;
        }

        return rewritten is null
            ? ChatMessageGuardResult.Unchanged(messages)
            : ChatMessageGuardResult.Modified(rewritten);
    }

    /// <summary>
    /// Evaluates one request message as input and keeps the verdict, so <see cref="GuardInputAsync"/>
    /// applies it to that message rather than evaluating it again. For hosts that block on a message
    /// <see cref="GuardInputAsync"/> would only replace.
    /// </summary>
    internal async ValueTask<GuardrailPipelineResult> EvaluateInputMessageAsync(
        GuardrailContext context, CancellationToken cancellationToken)
    {
        var result = await Pipeline.RunAsync(context, cancellationToken).ConfigureAwait(false);
        Remember(context.Text, result);
        return result;
    }

    // returns the messages with their tool results guarded, or null when no result changed
    private async ValueTask<List<ChatMessage>?> GuardRequestToolResultsAsync(
        IReadOnlyList<ChatMessage> messages, string? agentName, CancellationToken cancellationToken)
    {
        if (_requestTools is not { ChecksResults: true })
            return null;

        Dictionary<string, string>? toolNames = null;
        List<ChatMessage>? rewritten = null;

        for (var i = 0; i < messages.Count; i++)
        {
            var message = messages[i];
            if (_trustedRoles.Contains(message.Role))
                continue;

            List<AIContent>? contents = null;

            for (var j = 0; j < message.Contents.Count; j++)
            {
                if (message.Contents[j] is not FunctionResultContent result)
                    continue;

                var content = GuardrailChatContent.ToText(result.Result);
                if (string.IsNullOrEmpty(content))
                    continue;

                toolNames ??= ToolNamesByCallId(messages);
                var toolName = result.CallId is not null && toolNames.TryGetValue(result.CallId, out var name)
                    ? name
                    : result.CallId ?? "unknown";

                var verdict = await GetToolResultVerdictAsync(toolName, content, messages, i, agentName, cancellationToken)
                    .ConfigureAwait(false);

                var replacement = verdict.IsBlocked ? BlockedToolResultPlaceholder : verdict.ModifiedText;
                if (replacement is null)
                    continue;

                (contents ??= [.. message.Contents])[j] = WithResult(result, replacement);
            }

            if (contents is not null)
                (rewritten ??= [.. messages])[i] = WithContents(message, contents);
        }

        return rewritten;
    }

    private async ValueTask<Verdict> GetToolResultVerdictAsync(
        string toolName,
        string content,
        IReadOnlyList<ChatMessage> messages,
        int index,
        string? agentName,
        CancellationToken cancellationToken)
    {
        // keyed apart from message text: the same text is judged by other rules as a tool result, and
        // the tool's name decides which patterns apply
        var key = $"\0tool-result\0{toolName}\0{content}";
        if (_reuseVerdicts && _verdicts.TryGet(key, out var cached))
            return cached;

        var check = await _requestTools!.CheckResultAsync(
            toolName, content, messages.Take(index).ToList(), agentName, _stage, cancellationToken).ConfigureAwait(false);

        var verdict = new Verdict(check.IsBlocked, check.Content);
        if (_reuseVerdicts)
            _verdicts.Set(key, verdict);
        return verdict;
    }

    private static Dictionary<string, string> ToolNamesByCallId(IReadOnlyList<ChatMessage> messages)
    {
        var names = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var call in messages.SelectMany(m => m.Contents).OfType<FunctionCallContent>())
        {
            if (!string.IsNullOrEmpty(call.CallId) && !string.IsNullOrEmpty(call.Name))
                names[call.CallId] = call.Name;
        }

        return names;
    }

    private static FunctionResultContent WithResult(FunctionResultContent result, string content) =>
        new(result.CallId, content)
        {
            AdditionalProperties = result.AdditionalProperties
        };

    // the raw provider representation is not carried over - it still holds the original content
    private static ChatMessage WithContents(ChatMessage message, IList<AIContent> contents) =>
        new(message.Role, contents)
        {
            AuthorName = message.AuthorName,
            MessageId = message.MessageId,
            CreatedAt = message.CreatedAt,
            AdditionalProperties = message.AdditionalProperties
        };

    /// <summary>
    /// Guards the user and system messages of a model request, for hosts that see the whole request
    /// rather than only what the caller sent: history loaded from a store, messages a context provider
    /// added. Each distinct text is judged once and the verdict reused - from the same cache
    /// <see cref="GuardInputAsync"/> fills, so the caller's own messages, already judged as input, are
    /// not evaluated again. A blocked message is replaced with <see cref="RemovedMessagePlaceholder"/>
    /// and a rewritten one keeps its non-text content; the request as a whole is never blocked.
    /// </summary>
    /// <param name="messages">The request's messages.</param>
    /// <param name="agentName">The agent the request is for, when known.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The outcome: the messages to send on, with any rewrites applied.</returns>
    public async ValueTask<ChatMessageGuardResult> GuardRequestAsync(
        IReadOnlyList<ChatMessage> messages,
        string? agentName = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(messages);

        List<ChatMessage>? rewritten = null;

        for (var i = 0; i < messages.Count; i++)
        {
            var message = messages[i];
            if (!IsGuardedRequestMessage(message))
                continue;

            var verdict = await GetVerdictAsync(messages, i, agentName, cancellationToken).ConfigureAwait(false);

            if (verdict.IsBlocked)
                (rewritten ??= [.. messages])[i] = Removed(message);
            else if (verdict.ModifiedText is { } modifiedText)
                (rewritten ??= [.. messages])[i] = GuardrailChatContent.WithText(message, modifiedText);
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
        var contents = _guardToolContent ? responseMessages.SelectMany(m => m.Contents).ToList() : [];
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
        GuardrailContext? toolsContext = null;

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
                if (withTools)
                    toolsContext = context;

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
            toolContext.Properties[ToolContentOnlyKey] = true;
            AddToolProperties(toolContext, toolCalls, toolResults);

            var toolResult = await _checkPipeline.RunAsync(toolContext, cancellationToken).ConfigureAwait(false);
            if (toolResult.IsBlocked)
                return ChatMessageGuardResult.Blocked(responseMessages, toolResult.BlockingResult!, toolContext);

            toolsContext = toolContext;
        }

        // the tool-result rule hands sanitized results back through the property bag, not as text
        if (toolsContext is not null && ApplySanitizedToolResults(rewritten ?? responseMessages, toolsContext) is { } sanitized)
            rewritten = sanitized;

        var guarded = await GuardReasoningAsync(rewritten ?? responseMessages, requestMessages, agentName, cancellationToken)
            .ConfigureAwait(false);

        RememberReleased(guarded ?? rewritten ?? responseMessages);

        return guarded is null && rewritten is null
            ? ChatMessageGuardResult.Unchanged(responseMessages)
            : ChatMessageGuardResult.Modified(guarded ?? rewritten!);
    }

    // records the assistant text of a response that passed, so the same text coming back as history in
    // a later request is recognized as the model's own (see GetVerdictAsync). Kept in the verdict cache:
    // bounded, and local to this guard, so after a restart or on another instance the text is judged
    // like any other message
    private void RememberReleased(IReadOnlyList<ChatMessage> messages)
    {
        foreach (var message in messages)
        {
            if (message.Role == ChatRole.Assistant && !string.IsNullOrWhiteSpace(message.Text))
                _verdicts.Set(ReleasedKey(message.Text), default);
        }
    }

    // keyed apart from message text, so releasing a text as an answer says nothing about the same text
    // arriving in another role
    private static string ReleasedKey(string text) => $"\0released-assistant\0{text}";

    // substitutes the results the tool-result rule sanitized, matched in the order ExtractToolResults
    // produced them; returns null when there is nothing to substitute
    private static List<ChatMessage>? ApplySanitizedToolResults(IReadOnlyList<ChatMessage> messages, GuardrailContext context)
    {
        if (!context.Properties.TryGetValue(ToolResultGuardrailRule.SanitizedResultsKey, out var sanitizedObj) ||
            sanitizedObj is not IReadOnlyList<ToolResultEntry> { Count: > 0 } sanitized)
        {
            return null;
        }

        List<ChatMessage>? rewritten = null;
        var n = 0;

        for (var i = 0; i < messages.Count; i++)
        {
            var message = messages[i];
            List<AIContent>? contents = null;

            for (var j = 0; j < message.Contents.Count; j++)
            {
                if (message.Contents[j] is not FunctionResultContent result)
                    continue;

                var content = GuardrailChatContent.ToText(result.Result);
                if (string.IsNullOrEmpty(content))
                    continue;

                // the results no longer line up with what the rule saw: substitute nothing rather than
                // the wrong thing
                if (n >= sanitized.Count)
                    return null;

                var cleaned = sanitized[n++].Content;
                if (!string.Equals(cleaned, content, StringComparison.Ordinal))
                    (contents ??= [.. message.Contents])[j] = WithResult(result, cleaned);
            }

            if (contents is not null)
                (rewritten ??= [.. messages])[i] = WithContents(message, contents);
        }

        return n == sanitized.Count ? rewritten : null;
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

        // an assistant message this guard released on the way out is the model's own earlier answer,
        // already through the output rules: the input rules, written for what a caller types, would only
        // misjudge it. Anything else in an assistant message is whatever the caller wrote.
        if (messages[index].Role == ChatRole.Assistant && _verdicts.TryGet(ReleasedKey(text), out _))
            return default;

        if (_reuseVerdicts && _verdicts.TryGet(text, out var cached))
            return cached;

        // evaluate it against the conversation as it stood when it was the newest message
        var history = messages.Take(index + 1).ToList();
        var result = await Pipeline.RunAsync(
            CreateContext(text, GuardrailPhase.Input, history, agentName), cancellationToken).ConfigureAwait(false);

        Remember(text, result);
        return Verdict.From(result);
    }

    // keeps the verdict for reuse, unless it is one that should not outlive this evaluation: a rule
    // that could not reach a verdict (and failed open) may well reach one next time
    private void Remember(string text, GuardrailPipelineResult result)
    {
        if (!_reuseVerdicts)
            return;

        if (!result.AllResults.Any(r => r.IsError))
            _verdicts.Set(text, Verdict.From(result));
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

    private GuardrailContext CreateContext(
        string text, GuardrailPhase phase, IReadOnlyList<ChatMessage>? messages, string? agentName) => new()
        {
            Text = text,
            Phase = phase,
            Messages = messages,
            AgentName = agentName,
            Stage = _stage
        };

    // attachments go too: they belonged to a message the policy rejected
    private static ChatMessage Removed(ChatMessage message) =>
        new(message.Role, RemovedMessagePlaceholder)
        {
            AuthorName = message.AuthorName,
            MessageId = message.MessageId,
            CreatedAt = message.CreatedAt
        };

    private static bool IsGuardedRequestMessage(ChatMessage message) =>
        (message.Role == ChatRole.User || message.Role == ChatRole.System) && !string.IsNullOrWhiteSpace(message.Text);

    private static bool IsGuardedUserMessage(ChatMessage message) =>
        message.Role == ChatRole.User && !string.IsNullOrWhiteSpace(message.Text);

    // a user message the caller wrote, as opposed to one the host added to the request
    private bool IsCallerInput(ChatMessage message) =>
        IsGuardedUserMessage(message) && _isSupplemental?.Invoke(message) != true;

    private bool IsGuardedInputMessage(ChatMessage message) =>
        !_trustedRoles.Contains(message.Role) && !string.IsNullOrWhiteSpace(message.Text);

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
