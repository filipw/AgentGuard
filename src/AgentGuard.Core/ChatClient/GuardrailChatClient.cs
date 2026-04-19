using System.Runtime.CompilerServices;
using System.Text;
using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Builders;
using AgentGuard.Core.Guardrails;
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

    /// <summary>
    /// Creates a new <see cref="GuardrailChatClient"/> wrapping the given inner client.
    /// </summary>
    public GuardrailChatClient(IChatClient innerClient, IGuardrailPolicy policy, ILogger<GuardrailPipeline>? logger = null)
        : base(innerClient)
    {
        _policy = policy ?? throw new ArgumentNullException(nameof(policy));
        _pipeline = new GuardrailPipeline(policy, logger ?? NullLogger<GuardrailPipeline>.Instance);
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
            return new ChatResponse([new ChatMessage(ChatRole.Assistant, msg)]);
        }

        if (outputResult.WasModified)
            return new ChatResponse([new ChatMessage(ChatRole.Assistant, outputResult.FinalText)]);

        return response;
    }
}
