using System.Runtime.CompilerServices;
using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Guardrails;
using AgentGuard.Core.Ledger;
using AgentGuard.Core.Streaming;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.Logging;

namespace AgentGuard.Core.ChatClient;

/// <summary>
/// An <see cref="IChatClient"/> decorator that runs AgentGuard guardrails transparently on every call.
/// Input guardrails run on every user message in the request (see <see cref="ChatMessageGuard"/>)
/// before the inner client is invoked; output guardrails run on each assistant message of the
/// response, on its reasoning and on its tool calls and tool results. Conversation history is
/// automatically propagated to all rules from the messages passed to <see cref="GetResponseAsync"/> and
/// <see cref="GetStreamingResponseAsync"/>.
/// </summary>
/// <remarks>
/// <para>
/// Place the decorator inside a <c>FunctionInvokingChatClient</c> (add it after
/// <c>UseFunctionInvocation()</c> on a <see cref="ChatClientBuilder"/>) to have tool-call guardrails
/// vet every model turn before its tool calls run; outside it, they can only flag calls that have
/// already been executed.
/// </para>
/// <para>
/// A streamed response is buffered and guarded exactly like a non-streamed one, then replayed: as it
/// arrived when nothing changed, otherwise rebuilt from the guarded messages with its ids, usage,
/// finish reason and non-text content. With progressive streaming (see
/// <see cref="IGuardrailPolicy.ProgressiveStreaming"/>) the text streams as it arrives and
/// retraction/replacement events correct it, while everything else - tool calls and results, reasoning,
/// usage, finish reason - is held back until the stream has passed its final check.
/// </para>
/// </remarks>
public sealed class GuardrailChatClient : DelegatingChatClient
{
    private readonly ChatMessageGuard _guard;
    private readonly IGuardrailPolicy _policy;
    private readonly bool _ownsPolicy;

    /// <summary>
    /// Creates a new <see cref="GuardrailChatClient"/> wrapping the given inner client.
    /// </summary>
    /// <param name="innerClient">The client to decorate.</param>
    /// <param name="policy">The guardrail policy to enforce.</param>
    /// <param name="logger">Optional logger for the pipeline.</param>
    /// <param name="ledger">
    /// Optional decision ledger. Supply it to record one hash-chained entry per evaluation; the
    /// decorator builds its own pipeline, so a ledger registered in DI does not reach it otherwise.
    /// </param>
    public GuardrailChatClient(
        IChatClient innerClient,
        IGuardrailPolicy policy,
        ILogger<GuardrailPipeline>? logger = null,
        IGuardrailLedger? ledger = null)
        : this(innerClient, policy, logger, ledger, ownsPolicy: false)
    {
    }

    internal GuardrailChatClient(
        IChatClient innerClient,
        IGuardrailPolicy policy,
        ILogger<GuardrailPipeline>? logger,
        IGuardrailLedger? ledger,
        bool ownsPolicy)
        : base(innerClient)
    {
        _policy = policy ?? throw new ArgumentNullException(nameof(policy));
        _ownsPolicy = ownsPolicy;
        _guard = new ChatMessageGuard(policy, logger, ledger);
    }

    /// <summary>
    /// Well-known key used in <see cref="ChatResponseUpdate.AdditionalProperties"/> to carry
    /// <see cref="StreamingGuardrailEvent"/> instances during progressive streaming.
    /// </summary>
    public const string GuardrailEventPropertyKey = "agentguard.event";

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        // a policy this decorator built is its to release: some rules hold ONNX sessions or an
        // HttpClient. A policy handed in by the caller stays the caller's.
        if (disposing && _ownsPolicy)
        {
            (_policy as IDisposable)?.Dispose();
        }

        base.Dispose(disposing);
    }

    /// <inheritdoc/>
    public override async Task<ChatResponse> GetResponseAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        var messageList = messages.ToList();

        // input guardrails cover every user message, with the full conversation as history
        var (inputBlocked, processedMessages) = await RunInputGuardrailsAsync(messageList, cancellationToken);
        if (inputBlocked is not null)
            return inputBlocked;

        var response = await base.GetResponseAsync(processedMessages, options, cancellationToken);

        return await RunOutputGuardrailsAsync(response, processedMessages, cancellationToken);
    }

    /// <inheritdoc/>
    public override async IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? options = null,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        var messageList = messages.ToList();

        // input guardrails run before streaming begins
        var (inputBlocked, processedMessages) = await RunInputGuardrailsAsync(messageList, cancellationToken);
        if (inputBlocked is not null)
        {
            yield return new ChatResponseUpdate(ChatRole.Assistant, inputBlocked.Messages.FirstOrDefault()?.Text ?? "");
            yield break;
        }

        // a policy that opted into progressive streaming gets it here too; buffering the whole
        // response would silently ignore the ProgressiveStreaming options it configured
        var stream = _policy.ProgressiveStreaming is not null
            ? StreamProgressivelyAsync(processedMessages, options, cancellationToken)
            : StreamBufferedAsync(processedMessages, options, cancellationToken);

        await foreach (var update in stream)
            yield return update;
    }

    private async IAsyncEnumerable<ChatResponseUpdate> StreamBufferedAsync(
        IReadOnlyList<ChatMessage> processedMessages,
        ChatOptions? options,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var updates = new List<ChatResponseUpdate>();
        await foreach (var update in base.GetStreamingResponseAsync(processedMessages, options, cancellationToken))
            updates.Add(update);

        // the buffered response is guarded exactly like a non-streamed one: message by message
        var response = updates.ToChatResponse();
        var result = await _guard.GuardOutputAsync(
            [.. response.Messages], processedMessages, agentName: null, cancellationToken);

        if (result.IsBlocked)
        {
            var msg = await _policy.ViolationHandler.HandleViolationAsync(
                result.BlockingResult!, result.BlockingContext!, cancellationToken);

            // a blocked response must not carry any of the original content through
            yield return new ChatResponseUpdate(ChatRole.Assistant, msg)
            {
                ResponseId = response.ResponseId,
                ConversationId = response.ConversationId,
                ModelId = response.ModelId,
                CreatedAt = response.CreatedAt
            };
            yield break;
        }

        if (!result.WasModified)
        {
            foreach (var update in updates)
                yield return update;
            yield break;
        }

        response.ContinuationToken = LastContinuationToken(updates);
        foreach (var update in GuardrailChatContent.ToUpdates(response, result.Messages))
            yield return update;
    }

    private async IAsyncEnumerable<ChatResponseUpdate> StreamProgressivelyAsync(
        IReadOnlyList<ChatMessage> processedMessages,
        ChatOptions? options,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var streamingPipeline = new StreamingGuardrailPipeline(
            _policy, _policy.ProgressiveStreaming, ledger: _guard.Pipeline.Ledger);

        var outputContext = new GuardrailContext
        {
            Text = "",
            Phase = GuardrailPhase.Output,
            Messages = processedMessages
        };

        var upstream = new ProgressiveUpstream();
        var textStream = upstream.ReadTextAsync(
            base.GetStreamingResponseAsync(processedMessages, options, cancellationToken), cancellationToken);

        StreamingFinalResult? final = null;
        var shownLength = 0;

        await foreach (var output in streamingPipeline.ProcessStreamAsync(
            textStream, outputContext, _policy.ViolationHandler, cancellationToken))
        {
            switch (output.Type)
            {
                case StreamingOutputType.TextChunk:
                    shownLength += output.Text!.Length;
                    yield return TextUpdate(output.Text, upstream.Current);
                    break;

                case StreamingOutputType.GuardrailEvent:
                    if (output.GuardrailEvent!.Type == StreamingGuardrailEventType.Replacement)
                        shownLength = output.GuardrailEvent.ReplacementText?.Length ?? 0;
                    yield return EventUpdate(output.GuardrailEvent, upstream.Current);
                    break;

                case StreamingOutputType.Completed:
                    final = output.FinalResult;
                    break;
            }
        }

        // the retraction already replaced a blocked response; what was held back goes with it
        if (final is { IsBlocked: true })
            yield break;

        // tool calls, tool results and reasoning were held back while the text streamed: check them now
        var response = upstream.All.ToChatResponse();
        var result = await _guard.GuardToolsAndReasoningAsync(
            [.. response.Messages], processedMessages, agentName: null, cancellationToken);

        if (result.IsBlocked)
        {
            var msg = await _policy.ViolationHandler.HandleViolationAsync(
                result.BlockingResult!, result.BlockingContext!, cancellationToken);
            yield return EventUpdate(StreamingGuardrailEvent.Retract(result.BlockingResult!, shownLength), upstream.Current);
            yield return EventUpdate(StreamingGuardrailEvent.Replace(msg, result.BlockingResult!, shownLength), upstream.Current);
            yield break;
        }

        if (!result.WasModified)
        {
            foreach (var update in upstream.Held)
                yield return update;
            yield break;
        }

        // the text has already been delivered, so only the rest of the guarded messages goes out
        response.ContinuationToken = LastContinuationToken(upstream.All);
        foreach (var update in GuardrailChatContent.ToUpdates(response, WithoutText(result.Messages)))
            yield return update;
    }

    private static IEnumerable<ChatMessage> WithoutText(IEnumerable<ChatMessage> messages) =>
        messages
            .Select(message => string.IsNullOrEmpty(message.Text) ? message : GuardrailChatContent.WithText(message, ""))
            .Where(message => message.Contents.Count > 0 || message.AdditionalProperties is { Count: > 0 });

    private static ResponseContinuationToken? LastContinuationToken(List<ChatResponseUpdate> updates) =>
        updates.LastOrDefault(update => update.ContinuationToken is not null)?.ContinuationToken;

    // a streamed chunk keeps the ids of the update it came from
    private static ChatResponseUpdate TextUpdate(string text, ChatResponseUpdate? source) =>
        new(source?.Role ?? ChatRole.Assistant, text)
        {
            AuthorName = source?.AuthorName,
            MessageId = source?.MessageId,
            ResponseId = source?.ResponseId,
            ConversationId = source?.ConversationId,
            ModelId = source?.ModelId,
            CreatedAt = source?.CreatedAt
        };

    private static ChatResponseUpdate EventUpdate(StreamingGuardrailEvent guardrailEvent, ChatResponseUpdate? source)
    {
        var update = TextUpdate(guardrailEvent.ReplacementText ?? "", source);
        update.AdditionalProperties = new() { [GuardrailEventPropertyKey] = guardrailEvent };
        return update;
    }

    private async Task<(ChatResponse? blocked, IReadOnlyList<ChatMessage> processedMessages)> RunInputGuardrailsAsync(
        List<ChatMessage> messages,
        CancellationToken cancellationToken)
    {
        var result = await _guard.GuardInputAsync(messages, agentName: null, cancellationToken);

        if (result.IsBlocked)
        {
            var msg = await _policy.ViolationHandler.HandleViolationAsync(
                result.BlockingResult!, result.BlockingContext!, cancellationToken);
            return (new ChatResponse([new ChatMessage(ChatRole.Assistant, msg)]), messages);
        }

        return (null, result.Messages);
    }

    private async Task<ChatResponse> RunOutputGuardrailsAsync(
        ChatResponse response,
        IReadOnlyList<ChatMessage> messages,
        CancellationToken cancellationToken)
    {
        var responseMessages = response.Messages as IReadOnlyList<ChatMessage> ?? [.. response.Messages];
        var result = await _guard.GuardOutputAsync(responseMessages, messages, agentName: null, cancellationToken);

        if (result.IsBlocked)
        {
            var msg = await _policy.ViolationHandler.HandleViolationAsync(
                result.BlockingResult!, result.BlockingContext!, cancellationToken);

            // a blocked response must not carry any of the original content through
            return WithMessages(response, [new ChatMessage(ChatRole.Assistant, msg)], blocked: true);
        }

        return result.WasModified
            ? WithMessages(response, [.. result.Messages], blocked: false)
            : response;
    }

    /// <summary>
    /// Rebuilds a response around new messages while preserving the response-level metadata (id,
    /// usage, model, finish reason). A blocked response also drops the continuation token, so the rest
    /// of it can't be fetched.
    /// </summary>
    private static ChatResponse WithMessages(ChatResponse response, IList<ChatMessage> messages, bool blocked) =>
        new(messages)
        {
            ResponseId = response.ResponseId,
            ConversationId = response.ConversationId,
            ModelId = response.ModelId,
            CreatedAt = response.CreatedAt,
            FinishReason = response.FinishReason,
            Usage = response.Usage,
            ContinuationToken = blocked ? null : response.ContinuationToken,
            AdditionalProperties = response.AdditionalProperties
        };

    // splits the upstream stream: its text goes to the streaming pipeline as it arrives, everything
    // else waits in Held until the stream has passed its final check
    private sealed class ProgressiveUpstream
    {
        public List<ChatResponseUpdate> All { get; } = [];

        public List<ChatResponseUpdate> Held { get; } = [];

        public ChatResponseUpdate? Current { get; private set; }

        public async IAsyncEnumerable<string> ReadTextAsync(
            IAsyncEnumerable<ChatResponseUpdate> updates,
            [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            await foreach (var update in updates.WithCancellation(cancellationToken))
            {
                All.Add(update);
                Current = update;

                var text = update.Text;
                if (string.IsNullOrEmpty(text))
                {
                    Held.Add(update);
                    continue;
                }

                var rest = GuardrailChatContent.WithText(update, "");
                if (rest.Contents.Count > 0 || rest.FinishReason is not null ||
                    rest.ContinuationToken is not null || rest.AdditionalProperties is { Count: > 0 })
                {
                    Held.Add(rest);
                }

                yield return text;
            }
        }
    }
}
