using System.Runtime.CompilerServices;
using System.Text;
using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Guardrails;
using AgentGuard.Core.Ledger;
using AgentGuard.Core.Streaming;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace AgentGuard.Core.ChatClient;

/// <summary>
/// An <see cref="IChatClient"/> decorator that runs AgentGuard guardrails transparently on every call.
/// Input guardrails run on the last user message before the inner client is invoked.
/// Output guardrails run on the response text before it is returned to the caller.
/// Conversation history is automatically propagated to all rules from the messages passed to
/// <see cref="GetResponseAsync"/> and <see cref="GetStreamingResponseAsync"/>.
/// </summary>
public sealed class GuardrailChatClient : DelegatingChatClient
{
    private readonly GuardrailPipeline _pipeline;
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

        // Run input guardrails on the last user message, with full conversation history
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
        List<ChatMessage> processedMessages,
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

        if (!string.IsNullOrWhiteSpace(fullText))
        {
            var outputContext = new GuardrailContext
            {
                Text = fullText,
                Phase = GuardrailPhase.Output,
                Messages = processedMessages
            };

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
                yield return new ChatResponseUpdate(ChatRole.Assistant, outputResult.FinalText);
                yield break;
            }
        }

        // Output passed guardrails - yield all original chunks
        foreach (var chunk in chunks)
            yield return chunk;
    }

    private async IAsyncEnumerable<ChatResponseUpdate> StreamProgressivelyAsync(
        List<ChatMessage> processedMessages,
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

        var textStream = ExtractTextAsync(
            base.GetStreamingResponseAsync(processedMessages, options, cancellationToken), cancellationToken);

        await foreach (var output in streamingPipeline.ProcessStreamAsync(
            textStream, outputContext, _policy.ViolationHandler, cancellationToken))
        {
            switch (output.Type)
            {
                case StreamingOutputType.TextChunk:
                    yield return new ChatResponseUpdate(ChatRole.Assistant, output.Text);
                    break;

                case StreamingOutputType.GuardrailEvent:
                    var eventUpdate = new ChatResponseUpdate(
                        ChatRole.Assistant, output.GuardrailEvent?.ReplacementText ?? "");
                    eventUpdate.AdditionalProperties ??= [];
                    eventUpdate.AdditionalProperties[GuardrailEventPropertyKey] = output.GuardrailEvent!;
                    yield return eventUpdate;
                    break;
            }
        }
    }

    /// <summary>
    /// Well-known key used in <see cref="ChatResponseUpdate.AdditionalProperties"/> to carry
    /// <see cref="StreamingGuardrailEvent"/> instances during progressive streaming.
    /// </summary>
    public const string GuardrailEventPropertyKey = "agentguard.event";

    private static async IAsyncEnumerable<string> ExtractTextAsync(
        IAsyncEnumerable<ChatResponseUpdate> updates,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        await foreach (var update in updates.WithCancellation(cancellationToken))
        {
            if (!string.IsNullOrEmpty(update.Text))
                yield return update.Text;
        }
    }

    private async Task<(ChatResponse? blocked, List<ChatMessage> processedMessages)> RunInputGuardrailsAsync(
        List<ChatMessage> messages,
        CancellationToken cancellationToken)
    {
        // Evaluate the last user message; pass the full message list as conversation history
        var lastUserMessage = messages.LastOrDefault(m => m.Role == ChatRole.User);
        var inputText = lastUserMessage?.Text ?? "";

        if (string.IsNullOrWhiteSpace(inputText))
            return (null, messages);

        var inputContext = new GuardrailContext
        {
            Text = inputText,
            Phase = GuardrailPhase.Input,
            Messages = messages
        };

        var inputResult = await _pipeline.RunAsync(inputContext, cancellationToken);

        if (inputResult.IsBlocked)
        {
            var msg = await _policy.ViolationHandler.HandleViolationAsync(
                inputResult.BlockingResult!, inputContext, cancellationToken);
            return (new ChatResponse([new ChatMessage(ChatRole.Assistant, msg)]), messages);
        }

        if (inputResult.WasModified && lastUserMessage is not null)
        {
            var modified = new List<ChatMessage>(messages);
            var lastUserIdx = modified.LastIndexOf(lastUserMessage);
            modified[lastUserIdx] = new ChatMessage(lastUserMessage.Role, inputResult.FinalText);
            return (null, modified);
        }

        return (null, messages);
    }

    private async Task<ChatResponse> RunOutputGuardrailsAsync(
        ChatResponse response,
        List<ChatMessage> messages,
        CancellationToken cancellationToken)
    {
        var responseText = response.Text ?? "";

        if (string.IsNullOrWhiteSpace(responseText))
            return response;

        var outputContext = new GuardrailContext
        {
            Text = responseText,
            Phase = GuardrailPhase.Output,
            Messages = messages
        };

        var outputResult = await _pipeline.RunAsync(outputContext, cancellationToken);

        if (outputResult.IsBlocked)
        {
            var msg = await _policy.ViolationHandler.HandleViolationAsync(
                outputResult.BlockingResult!, outputContext, cancellationToken);
            return ReplaceText(response, msg, keepOtherContent: false);
        }

        if (outputResult.WasModified)
            return ReplaceText(response, outputResult.FinalText, keepOtherContent: true);

        return response;
    }

    /// <summary>
    /// Rebuilds a response around new assistant text while preserving the response-level metadata
    /// (id, usage, model, finish reason) and, for a modification, the non-text content such as
    /// function calls. Returning a bare <c>new ChatResponse([...])</c> would drop all of it.
    /// </summary>
    private static ChatResponse ReplaceText(ChatResponse response, string text, bool keepOtherContent)
    {
        List<ChatMessage> messages;

        if (keepOtherContent)
        {
            messages = [.. response.Messages];
            var index = messages.FindLastIndex(m => m.Role == ChatRole.Assistant && !string.IsNullOrEmpty(m.Text));

            if (index >= 0)
            {
                var original = messages[index];
                var contents = original.Contents
                    .Where(c => c is not TextContent)
                    .Prepend<AIContent>(new TextContent(text))
                    .ToList();

                messages[index] = new ChatMessage(original.Role, contents)
                {
                    AuthorName = original.AuthorName,
                    MessageId = original.MessageId,
                    AdditionalProperties = original.AdditionalProperties
                };
            }
            else
            {
                messages.Add(new ChatMessage(ChatRole.Assistant, text));
            }
        }
        else
        {
            // a blocked response must not carry any of the original content through
            messages = [new ChatMessage(ChatRole.Assistant, text)];
        }

        return new ChatResponse(messages)
        {
            ResponseId = response.ResponseId,
            ConversationId = response.ConversationId,
            ModelId = response.ModelId,
            CreatedAt = response.CreatedAt,
            FinishReason = response.FinishReason,
            Usage = response.Usage,
            AdditionalProperties = response.AdditionalProperties
        };
    }
}
