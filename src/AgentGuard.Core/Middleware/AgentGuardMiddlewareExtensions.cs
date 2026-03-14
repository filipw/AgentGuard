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
                var lastMessage = messages.LastOrDefault();
                var inputText = lastMessage?.Text ?? "";

                if (!string.IsNullOrEmpty(inputText))
                {
                    var inputContext = new GuardrailContext
                    {
                        Text = inputText,
                        Phase = GuardrailPhase.Input,
                        Messages = messages.ToList(),
                        AgentName = innerAgent.Name
                    };

                    var inputResult = await pipeline.RunAsync(inputContext, ct);

                    if (inputResult.IsBlocked)
                    {
                        var msg = await policy.ViolationHandler.HandleViolationAsync(inputResult.BlockingResult!, inputContext, ct);
                        return new AgentResponse([new ChatMessage(ChatRole.Assistant, msg)]);
                    }

                    if (inputResult.WasModified && lastMessage is not null)
                    {
                        var modified = messages.ToList();
                        modified[^1] = new ChatMessage(lastMessage.Role, inputResult.FinalText);
                        messages = modified;
                    }
                }

                var response = await innerAgent.RunAsync(messages, session, options, ct);

                var responseText = response.Messages
                    .Where(m => m.Role == ChatRole.Assistant)
                    .Select(m => m.Text)
                    .LastOrDefault() ?? "";

                if (!string.IsNullOrEmpty(responseText))
                {
                    var outputContext = new GuardrailContext
                    {
                        Text = responseText,
                        Phase = GuardrailPhase.Output,
                        Messages = messages.ToList(),
                        AgentName = innerAgent.Name
                    };

                    var outputResult = await pipeline.RunAsync(outputContext, ct);

                    if (outputResult.IsBlocked)
                    {
                        var msg = await policy.ViolationHandler.HandleViolationAsync(outputResult.BlockingResult!, outputContext, ct);
                        return new AgentResponse([new ChatMessage(ChatRole.Assistant, msg)]);
                    }

                    if (outputResult.WasModified)
                        return new AgentResponse([new ChatMessage(ChatRole.Assistant, outputResult.FinalText)]);
                }

                return response;
            },
            runStreamingFunc: null
        );
    }
}
