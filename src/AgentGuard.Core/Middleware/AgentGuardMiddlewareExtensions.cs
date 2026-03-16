using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Builders;
using AgentGuard.Core.Guardrails;
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace AgentGuard.Core.Middleware;

public static class AgentGuardMiddlewareExtensions
{
    public static AIAgentBuilder UseAgentGuard(
        this AIAgentBuilder builder, Action<GuardrailPolicyBuilder> configure, ILogger<GuardrailPipeline>? logger = null)
    {
        var policyBuilder = new GuardrailPolicyBuilder();
        configure(policyBuilder);
        return builder.UseAgentGuard(policyBuilder.Build(), logger);
    }

    public static AIAgentBuilder UseAgentGuard(
        this AIAgentBuilder builder, IGuardrailPolicy policy, ILogger<GuardrailPipeline>? logger = null)
    {
        var pipeline = new GuardrailPipeline(policy, logger ?? NullLogger<GuardrailPipeline>.Instance);

        return builder.Use(
            runFunc: async (messages, session, options, innerAgent, ct) =>
            {
                var (blocked, processedMessages) = await RunInputGuardrails(pipeline, policy, messages, innerAgent.Name, ct);
                if (blocked is not null)
                    return blocked;

                var response = await innerAgent.RunAsync(processedMessages, session, options, ct);

                return await RunOutputGuardrails(pipeline, policy, response, processedMessages, innerAgent.Name, ct);
            },
            runStreamingFunc: (messages, session, options, innerAgent, ct) =>
            {
                return StreamWithGuardrails(pipeline, policy, messages, session, options, innerAgent, ct);
            }
        );
    }

    private static async Task<(AgentResponse? blocked, IEnumerable<ChatMessage> messages)> RunInputGuardrails(
        GuardrailPipeline pipeline,
        IGuardrailPolicy policy,
        IEnumerable<ChatMessage> messages,
        string? agentName,
        CancellationToken ct)
    {
        var lastMessage = messages.LastOrDefault();
        var inputText = lastMessage?.Text ?? "";

        if (string.IsNullOrEmpty(inputText))
            return (null, messages);

        var inputContext = new GuardrailContext
        {
            Text = inputText,
            Phase = GuardrailPhase.Input,
            Messages = messages.ToList(),
            AgentName = agentName
        };

        var inputResult = await pipeline.RunAsync(inputContext, ct);

        if (inputResult.IsBlocked)
        {
            var msg = await policy.ViolationHandler.HandleViolationAsync(inputResult.BlockingResult!, inputContext, ct);
            return (new AgentResponse([new ChatMessage(ChatRole.Assistant, msg)]), messages);
        }

        if (inputResult.WasModified && lastMessage is not null)
        {
            var modified = messages.ToList();
            modified[^1] = new ChatMessage(lastMessage.Role, inputResult.FinalText);
            return (null, modified);
        }

        return (null, messages);
    }

    private static async Task<AgentResponse> RunOutputGuardrails(
        GuardrailPipeline pipeline,
        IGuardrailPolicy policy,
        AgentResponse response,
        IEnumerable<ChatMessage> messages,
        string? agentName,
        CancellationToken ct)
    {
        var responseText = response.Messages
            .Where(m => m.Role == ChatRole.Assistant)
            .Select(m => m.Text)
            .LastOrDefault() ?? "";

        if (string.IsNullOrEmpty(responseText))
            return response;

        var outputContext = new GuardrailContext
        {
            Text = responseText,
            Phase = GuardrailPhase.Output,
            Messages = messages.ToList(),
            AgentName = agentName
        };

        var outputResult = await pipeline.RunAsync(outputContext, ct);

        if (outputResult.IsBlocked)
        {
            var msg = await policy.ViolationHandler.HandleViolationAsync(outputResult.BlockingResult!, outputContext, ct);
            return new AgentResponse([new ChatMessage(ChatRole.Assistant, msg)]);
        }

        if (outputResult.WasModified)
            return new AgentResponse([new ChatMessage(ChatRole.Assistant, outputResult.FinalText)]);

        return response;
    }

    private static async IAsyncEnumerable<AgentResponseUpdate> StreamWithGuardrails(
        GuardrailPipeline pipeline,
        IGuardrailPolicy policy,
        IEnumerable<ChatMessage> messages,
        AgentSession? session,
        AgentRunOptions? options,
        AIAgent innerAgent,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        // Run input guardrails before streaming
        var (blocked, processedMessages) = await RunInputGuardrails(pipeline, policy, messages, innerAgent.Name, ct);
        if (blocked is not null)
        {
            var text = blocked.Messages.FirstOrDefault()?.Text ?? "";
            yield return new AgentResponseUpdate(ChatRole.Assistant, text);
            yield break;
        }

        // Buffer the streaming output so we can run output guardrails
        var chunks = new List<AgentResponseUpdate>();
        var textBuilder = new System.Text.StringBuilder();

        await foreach (var update in innerAgent.RunStreamingAsync(processedMessages, session, options, ct))
        {
            chunks.Add(update);
            if (!string.IsNullOrEmpty(update.Text))
                textBuilder.Append(update.Text);
        }

        var fullText = textBuilder.ToString();

        // Run output guardrails on the accumulated text
        if (!string.IsNullOrEmpty(fullText))
        {
            var outputContext = new GuardrailContext
            {
                Text = fullText,
                Phase = GuardrailPhase.Output,
                Messages = processedMessages.ToList(),
                AgentName = innerAgent.Name
            };

            var outputResult = await pipeline.RunAsync(outputContext, ct);

            if (outputResult.IsBlocked)
            {
                var msg = await policy.ViolationHandler.HandleViolationAsync(outputResult.BlockingResult!, outputContext, ct);
                yield return new AgentResponseUpdate(ChatRole.Assistant, msg);
                yield break;
            }

            if (outputResult.WasModified)
            {
                yield return new AgentResponseUpdate(ChatRole.Assistant, outputResult.FinalText);
                yield break;
            }
        }

        // Output passed guardrails — yield all original chunks
        foreach (var chunk in chunks)
        {
            yield return chunk;
        }
    }
}
