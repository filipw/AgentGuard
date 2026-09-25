using System.Runtime.CompilerServices;
using System.Text;
using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Guardrails;
using AgentGuard.Core.Ledger;
using AgentGuard.Core.Rules.ToolCall;
using AgentGuard.Core.Rules.ToolResult;
using AgentGuard.Core.Streaming;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace AgentGuard.Core.ChatClient;

/// <summary>
/// An <see cref="IChatClient"/> decorator that runs AgentGuard guardrails transparently on every call.
/// Input guardrails run on every user message in the request (see <see cref="ChatMessageGuard"/>)
/// before the inner client is invoked; output guardrails run on each assistant message of the
/// response and on its tool calls and tool results. Conversation history is automatically propagated
/// to all rules from the messages passed to <see cref="GetResponseAsync"/> and
/// <see cref="GetStreamingResponseAsync"/>.
/// </summary>
/// <remarks>
/// Place the decorator inside a <c>FunctionInvokingChatClient</c> (add it after
/// <c>UseFunctionInvocation()</c> on a <see cref="ChatClientBuilder"/>) to have tool-call guardrails
/// vet every model turn before its tool calls run; outside it, they can only flag calls that have
/// already been executed.
/// </remarks>
public sealed class GuardrailChatClient : DelegatingChatClient
{
    private readonly GuardrailPipeline _pipeline;
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
        _pipeline = new GuardrailPipeline(policy, logger ?? NullLogger<GuardrailPipeline>.Instance, ledger);
        _guard = new ChatMessageGuard(_pipeline);
    }

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

        // Call inner client
        var response = await base.GetResponseAsync(processedMessages, options, cancellationToken);

        // Run output guardrails on the response
        return await RunOutputGuardrailsAsync(response, processedMessages, cancellationToken);
    }

    /// <inheritdoc/>
    public override async IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? options = null,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        var messageList = messages.ToList();

        // Run input guardrails before streaming begins
        var (inputBlocked, processedMessages) = await RunInputGuardrailsAsync(messageList, cancellationToken);
        if (inputBlocked is not null)
        {
            // Yield the violation message as a single update
            var text = inputBlocked.Messages.FirstOrDefault()?.Text ?? "";
            yield return new ChatResponseUpdate(ChatRole.Assistant, text);
            yield break;
        }

        // A policy that opted into progressive streaming gets it here too; buffering the whole
        // response would silently ignore the ProgressiveStreaming options it configured.
        if (_policy.ProgressiveStreaming is not null)
        {
            await foreach (var update in StreamProgressivelyAsync(processedMessages, options, cancellationToken))
                yield return update;
            yield break;
        }

        await foreach (var update in StreamBufferedAsync(processedMessages, options, cancellationToken))
            yield return update;
    }

    private async IAsyncEnumerable<ChatResponseUpdate> StreamBufferedAsync(
        IReadOnlyList<ChatMessage> processedMessages,
        ChatOptions? options,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        // Buffer streaming output so output guardrails can evaluate the full response
        var chunks = new List<ChatResponseUpdate>();
        var textBuilder = new StringBuilder();

        await foreach (var update in base.GetStreamingResponseAsync(processedMessages, options, cancellationToken))
        {
            chunks.Add(update);
            if (!string.IsNullOrEmpty(update.Text))
                textBuilder.Append(update.Text);
        }

        var fullText = textBuilder.ToString();
        var contents = chunks.SelectMany(c => c.Contents).ToList();
        var toolCalls = GuardrailChatContent.ExtractToolCalls(contents);
        var toolResults = GuardrailChatContent.ExtractToolResults(contents);

        if (!string.IsNullOrWhiteSpace(fullText) || toolCalls.Count > 0 || toolResults.Count > 0)
        {
            var outputContext = new GuardrailContext
            {
                Text = fullText,
                Phase = GuardrailPhase.Output,
                Messages = processedMessages
            };

            AddToolProperties(outputContext, toolCalls, toolResults);

            var outputResult = await _pipeline.RunAsync(outputContext, cancellationToken);

            if (outputResult.IsBlocked)
            {
                var msg = await _policy.ViolationHandler.HandleViolationAsync(
                    outputResult.BlockingResult!, outputContext, cancellationToken);
                yield return new ChatResponseUpdate(ChatRole.Assistant, msg);
                yield break;
            }

            if (outputResult.WasModified)
            {
                foreach (var update in ReplaceStreamedText(chunks, outputResult.FinalText))
                    yield return update;
                yield break;
            }
        }

        // Output passed guardrails - yield all original chunks
        foreach (var chunk in chunks)
            yield return chunk;
    }

    // the rewritten text goes out as one update, followed by everything else the stream carried -
    // function calls, usage, finish reason, ids - so a rewrite doesn't break the tool loop around it
    private static IEnumerable<ChatResponseUpdate> ReplaceStreamedText(List<ChatResponseUpdate> chunks, string text)
    {
        var template = chunks.FirstOrDefault(c => !string.IsNullOrEmpty(c.Text));

        yield return new ChatResponseUpdate(template?.Role ?? ChatRole.Assistant, text)
        {
            AuthorName = template?.AuthorName,
            MessageId = template?.MessageId,
            ResponseId = template?.ResponseId,
            ConversationId = template?.ConversationId,
            CreatedAt = template?.CreatedAt,
            ModelId = template?.ModelId
        };

        foreach (var chunk in chunks)
        {
            var rest = GuardrailChatContent.ReplaceText(chunk.Contents, "");
            if (rest.Count == 0 && chunk.FinishReason is null && chunk.ContinuationToken is null)
                continue;

            yield return new ChatResponseUpdate(chunk.Role, rest)
            {
                AuthorName = chunk.AuthorName,
                MessageId = chunk.MessageId,
                ResponseId = chunk.ResponseId,
                ConversationId = chunk.ConversationId,
                CreatedAt = chunk.CreatedAt,
                ModelId = chunk.ModelId,
                FinishReason = chunk.FinishReason,
                ContinuationToken = chunk.ContinuationToken,
                AdditionalProperties = chunk.AdditionalProperties
            };
        }
    }

    private async IAsyncEnumerable<ChatResponseUpdate> StreamProgressivelyAsync(
        IReadOnlyList<ChatMessage> processedMessages,
        ChatOptions? options,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var streamingPipeline = new StreamingGuardrailPipeline(
            _policy, _policy.ProgressiveStreaming, ledger: _pipeline.Ledger);

        var outputContext = new GuardrailContext
        {
            Text = "",
            Phase = GuardrailPhase.Output,
            Messages = processedMessages
        };

        // tool calls and results are collected while the text streams and evaluated at the end
        var collected = new List<AIContent>();
        var textStream = ExtractTextAsync(
            base.GetStreamingResponseAsync(processedMessages, options, cancellationToken), collected, cancellationToken);

        var shownLength = 0;

        await foreach (var output in streamingPipeline.ProcessStreamAsync(
            textStream, outputContext, _policy.ViolationHandler, cancellationToken))
        {
            switch (output.Type)
            {
                case StreamingOutputType.TextChunk:
                    shownLength += output.Text?.Length ?? 0;
                    yield return new ChatResponseUpdate(ChatRole.Assistant, output.Text);
                    break;

                case StreamingOutputType.GuardrailEvent:
                    if (output.GuardrailEvent?.Type == StreamingGuardrailEventType.Replacement)
                        shownLength = output.GuardrailEvent.ReplacementText?.Length ?? 0;
                    yield return EventUpdate(output.GuardrailEvent!);
                    break;

                case StreamingOutputType.Completed:
                    var toolCalls = GuardrailChatContent.ExtractToolCalls(collected);
                    var toolResults = GuardrailChatContent.ExtractToolResults(collected);
                    if (toolCalls.Count == 0 && toolResults.Count == 0)
                        break;

                    AddToolProperties(outputContext, toolCalls, toolResults);
                    var toolResult = await _pipeline.RunAsync(outputContext, cancellationToken);
                    if (toolResult.IsBlocked)
                    {
                        var msg = await _policy.ViolationHandler.HandleViolationAsync(
                            toolResult.BlockingResult!, outputContext, cancellationToken);
                        yield return EventUpdate(StreamingGuardrailEvent.Retract(toolResult.BlockingResult!, shownLength));
                        yield return EventUpdate(StreamingGuardrailEvent.Replace(msg, toolResult.BlockingResult!, shownLength));
                    }
                    break;
            }
        }
    }

    private static ChatResponseUpdate EventUpdate(StreamingGuardrailEvent guardrailEvent)
    {
        var update = new ChatResponseUpdate(ChatRole.Assistant, guardrailEvent.ReplacementText ?? "");
        update.AdditionalProperties ??= [];
        update.AdditionalProperties[GuardrailEventPropertyKey] = guardrailEvent;
        return update;
    }

    /// <summary>
    /// Well-known key used in <see cref="ChatResponseUpdate.AdditionalProperties"/> to carry
    /// <see cref="StreamingGuardrailEvent"/> instances during progressive streaming.
    /// </summary>
    public const string GuardrailEventPropertyKey = "agentguard.event";

    private static async IAsyncEnumerable<string> ExtractTextAsync(
        IAsyncEnumerable<ChatResponseUpdate> updates,
        List<AIContent> collected,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        await foreach (var update in updates.WithCancellation(cancellationToken))
        {
            collected.AddRange(update.Contents.Where(c => c is FunctionCallContent or FunctionResultContent));

            if (!string.IsNullOrEmpty(update.Text))
                yield return update.Text;
        }
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

    private static void AddToolProperties(
        GuardrailContext context, List<AgentToolCall> toolCalls, List<ToolResultEntry> toolResults)
    {
        if (toolCalls.Count > 0)
            context.Properties[ToolCallGuardrailRule.ToolCallsKey] = (IReadOnlyList<AgentToolCall>)toolCalls;

        if (toolResults.Count > 0)
            context.Properties[ToolResultGuardrailRule.ToolResultsKey] = (IReadOnlyList<ToolResultEntry>)toolResults;
    }
}
