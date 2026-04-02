using System.Diagnostics;
using System.Text;
using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Builders;
using AgentGuard.Core.Guardrails;
using AgentGuard.Core.Rules.ToolCall;
using AgentGuard.Core.Streaming;
using AgentGuard.Core.Telemetry;
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace AgentGuard.AgentFramework;

/// <summary>
/// Extension methods for integrating AgentGuard guardrails into the Microsoft Agent Framework pipeline.
/// </summary>
public static class AgentGuardMiddlewareExtensions
{
    /// <summary>
    /// Adds AgentGuard guardrails to the MAF agent pipeline using a fluent builder configuration.
    /// </summary>
    public static AIAgentBuilder UseAgentGuard(
        this AIAgentBuilder builder, Action<GuardrailPolicyBuilder> configure, ILogger<GuardrailPipeline>? logger = null)
    {
        var policyBuilder = new GuardrailPolicyBuilder();
        configure(policyBuilder);
        return builder.UseAgentGuard(policyBuilder.Build(), logger);
    }

    /// <summary>
    /// Adds AgentGuard guardrails to the MAF agent pipeline using a pre-built policy.
    /// </summary>
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
        using var inputActivity = AgentGuardTelemetry.ActivitySource.StartActivity(
            AgentGuardTelemetry.Spans.MiddlewareInput);

        inputActivity?.SetTag(AgentGuardTelemetry.Tags.AgentName, agentName);
        inputActivity?.SetTag(AgentGuardTelemetry.Tags.Phase, "input");

        var lastMessage = messages.LastOrDefault();
        var inputText = lastMessage?.Text ?? "";

        if (string.IsNullOrEmpty(inputText))
        {
            inputActivity?.SetTag(AgentGuardTelemetry.Tags.Outcome, AgentGuardTelemetry.Outcomes.Passed);
            return (null, messages);
        }

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
            inputActivity?.SetTag(AgentGuardTelemetry.Tags.Outcome, AgentGuardTelemetry.Outcomes.Blocked);
            inputActivity?.SetStatus(ActivityStatusCode.Error, inputResult.BlockingResult?.Reason);
            var msg = await policy.ViolationHandler.HandleViolationAsync(inputResult.BlockingResult!, inputContext, ct);
            return (new AgentResponse([new ChatMessage(ChatRole.Assistant, msg)]), messages);
        }

        if (inputResult.WasModified && lastMessage is not null)
        {
            inputActivity?.SetTag(AgentGuardTelemetry.Tags.Outcome, AgentGuardTelemetry.Outcomes.Modified);
            var modified = messages.ToList();
            modified[^1] = new ChatMessage(lastMessage.Role, inputResult.FinalText);
            return (null, modified);
        }

        inputActivity?.SetTag(AgentGuardTelemetry.Tags.Outcome, AgentGuardTelemetry.Outcomes.Passed);
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
        using var outputActivity = AgentGuardTelemetry.ActivitySource.StartActivity(
            AgentGuardTelemetry.Spans.MiddlewareOutput);

        outputActivity?.SetTag(AgentGuardTelemetry.Tags.AgentName, agentName);
        outputActivity?.SetTag(AgentGuardTelemetry.Tags.Phase, "output");

        var responseText = response.Messages
            .Where(m => m.Role == ChatRole.Assistant)
            .Select(m => m.Text)
            .LastOrDefault() ?? "";

        // extract tool calls from the response for ToolCallGuardrailRule
        var toolCalls = ExtractToolCalls(response.Messages);
        outputActivity?.SetTag(AgentGuardTelemetry.Tags.ToolCallCount, toolCalls.Count);

        // nothing to evaluate if no text and no tool calls
        if (string.IsNullOrEmpty(responseText) && toolCalls.Count == 0)
        {
            outputActivity?.SetTag(AgentGuardTelemetry.Tags.Outcome, AgentGuardTelemetry.Outcomes.Passed);
            return response;
        }

        var outputContext = new GuardrailContext
        {
            Text = responseText ?? "",
            Phase = GuardrailPhase.Output,
            Messages = messages.ToList(),
            AgentName = agentName
        };

        if (toolCalls.Count > 0)
            outputContext.Properties[ToolCallGuardrailRule.ToolCallsKey] = toolCalls;

        var outputResult = await pipeline.RunAsync(outputContext, ct);

        if (outputResult.IsBlocked)
        {
            outputActivity?.SetTag(AgentGuardTelemetry.Tags.Outcome, AgentGuardTelemetry.Outcomes.Blocked);
            outputActivity?.SetStatus(ActivityStatusCode.Error, outputResult.BlockingResult?.Reason);
            var msg = await policy.ViolationHandler.HandleViolationAsync(outputResult.BlockingResult!, outputContext, ct);
            return new AgentResponse([new ChatMessage(ChatRole.Assistant, msg)]);
        }

        if (outputResult.WasModified)
        {
            outputActivity?.SetTag(AgentGuardTelemetry.Tags.Outcome, AgentGuardTelemetry.Outcomes.Modified);
            return new AgentResponse([new ChatMessage(ChatRole.Assistant, outputResult.FinalText)]);
        }

        outputActivity?.SetTag(AgentGuardTelemetry.Tags.Outcome, AgentGuardTelemetry.Outcomes.Passed);
        return response;
    }

    /// <summary>
    /// Extracts <see cref="AgentToolCall"/> instances from MAF response messages by
    /// reading <see cref="FunctionCallContent"/> items embedded in the message contents.
    /// </summary>
    private static List<AgentToolCall> ExtractToolCalls(IEnumerable<ChatMessage> responseMessages)
    {
        var toolCalls = new List<AgentToolCall>();

        foreach (var message in responseMessages)
        {
            foreach (var fc in message.Contents.OfType<FunctionCallContent>())
            {
                var args = new Dictionary<string, string>();
                if (fc.Arguments is not null)
                {
                    foreach (var (key, value) in fc.Arguments)
                    {
                        args[key] = value?.ToString() ?? "";
                    }
                }

                toolCalls.Add(new AgentToolCall
                {
                    ToolName = fc.Name ?? "",
                    Arguments = args
                });
            }
        }

        return toolCalls;
    }

    /// <summary>
    /// Extracts <see cref="AgentToolCall"/> instances from streaming response updates.
    /// </summary>
    private static List<AgentToolCall> ExtractToolCallsFromUpdates(IEnumerable<AgentResponseUpdate> updates)
    {
        var toolCalls = new List<AgentToolCall>();

        foreach (var update in updates)
        {
            foreach (var fc in update.Contents.OfType<FunctionCallContent>())
            {
                var args = new Dictionary<string, string>();
                if (fc.Arguments is not null)
                {
                    foreach (var (key, value) in fc.Arguments)
                    {
                        args[key] = value?.ToString() ?? "";
                    }
                }

                toolCalls.Add(new AgentToolCall
                {
                    ToolName = fc.Name ?? "",
                    Arguments = args
                });
            }
        }

        return toolCalls;
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
        using var streamingActivity = AgentGuardTelemetry.ActivitySource.StartActivity(
            AgentGuardTelemetry.Spans.MiddlewareStreaming);

        streamingActivity?.SetTag(AgentGuardTelemetry.Tags.AgentName, innerAgent.Name);

        // run input guardrails before streaming
        var (blocked, processedMessages) = await RunInputGuardrails(pipeline, policy, messages, innerAgent.Name, ct);
        if (blocked is not null)
        {
            streamingActivity?.SetTag(AgentGuardTelemetry.Tags.Outcome, AgentGuardTelemetry.Outcomes.Blocked);
            var text = blocked.Messages.FirstOrDefault()?.Text ?? "";
            yield return new AgentResponseUpdate(ChatRole.Assistant, text);
            yield break;
        }

        // use progressive streaming if configured, otherwise buffer-then-release
        if (policy.ProgressiveStreaming is not null)
        {
            streamingActivity?.SetTag(AgentGuardTelemetry.Tags.StreamingStrategy, "progressive");
            await foreach (var update in StreamWithProgressiveGuardrails(
                pipeline, policy, processedMessages, session, options, innerAgent, ct))
            {
                yield return update;
            }
        }
        else
        {
            streamingActivity?.SetTag(AgentGuardTelemetry.Tags.StreamingStrategy, "buffered");
            await foreach (var update in StreamWithBufferedGuardrails(
                pipeline, policy, processedMessages, session, options, innerAgent, ct))
            {
                yield return update;
            }
        }

        streamingActivity?.SetTag(AgentGuardTelemetry.Tags.Outcome, AgentGuardTelemetry.Outcomes.Passed);
    }

    private static async IAsyncEnumerable<AgentResponseUpdate> StreamWithBufferedGuardrails(
        GuardrailPipeline pipeline,
        IGuardrailPolicy policy,
        IEnumerable<ChatMessage> processedMessages,
        AgentSession? session,
        AgentRunOptions? options,
        AIAgent innerAgent,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        // buffer the streaming output so we can run output guardrails
        var chunks = new List<AgentResponseUpdate>();
        var textBuilder = new StringBuilder();

        await foreach (var update in innerAgent.RunStreamingAsync(processedMessages, session, options, ct))
        {
            chunks.Add(update);
            if (!string.IsNullOrEmpty(update.Text))
                textBuilder.Append(update.Text);
        }

        var fullText = textBuilder.ToString();

        // extract tool calls from streaming chunks
        var toolCalls = ExtractToolCallsFromUpdates(chunks);

        // run output guardrails on the accumulated text and/or tool calls
        if (!string.IsNullOrEmpty(fullText) || toolCalls.Count > 0)
        {
            var outputContext = new GuardrailContext
            {
                Text = fullText ?? "",
                Phase = GuardrailPhase.Output,
                Messages = processedMessages.ToList(),
                AgentName = innerAgent.Name
            };

            if (toolCalls.Count > 0)
                outputContext.Properties[ToolCallGuardrailRule.ToolCallsKey] = toolCalls;

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

        // output passed guardrails - yield all original chunks
        foreach (var chunk in chunks)
        {
            yield return chunk;
        }
    }

    /// <summary>
    /// Well-known key used in <see cref="AgentResponseUpdate.AdditionalProperties"/>
    /// to carry <see cref="StreamingGuardrailEvent"/> instances during progressive streaming.
    /// </summary>
    public const string GuardrailEventPropertyKey = "agentguard.event";

    private static async IAsyncEnumerable<AgentResponseUpdate> StreamWithProgressiveGuardrails(
        GuardrailPipeline pipeline,
        IGuardrailPolicy policy,
        IEnumerable<ChatMessage> processedMessages,
        AgentSession? session,
        AgentRunOptions? options,
        AIAgent innerAgent,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        var streamingPipeline = new StreamingGuardrailPipeline(policy, policy.ProgressiveStreaming);

        var outputContext = new GuardrailContext
        {
            Text = "", // will be set per-evaluation inside the pipeline
            Phase = GuardrailPhase.Output,
            Messages = processedMessages.ToList(),
            AgentName = innerAgent.Name
        };

        // collect tool calls from streaming updates alongside text extraction.
        // tool calls are evaluated after the stream completes (FinalOnly semantics).
        var collectedToolCalls = new List<AgentToolCall>();
        var textStream = ExtractTextAndToolCalls(
            innerAgent.RunStreamingAsync(processedMessages, session, options, ct), collectedToolCalls, ct);

        await foreach (var output in streamingPipeline.ProcessStreamAsync(textStream, outputContext, policy.ViolationHandler, ct))
        {
            switch (output.Type)
            {
                case StreamingOutputType.TextChunk:
                    yield return new AgentResponseUpdate(ChatRole.Assistant, output.Text);
                    break;

                case StreamingOutputType.GuardrailEvent:
                    var eventUpdate = new AgentResponseUpdate(ChatRole.Assistant, output.GuardrailEvent?.ReplacementText ?? "");
                    eventUpdate.AdditionalProperties ??= [];
                    eventUpdate.AdditionalProperties[GuardrailEventPropertyKey] = output.GuardrailEvent!;
                    yield return eventUpdate;
                    break;

                case StreamingOutputType.Completed:
                    // after stream completes, evaluate any collected tool calls
                    if (collectedToolCalls.Count > 0)
                    {
                        outputContext.Properties[ToolCallGuardrailRule.ToolCallsKey] = (IReadOnlyList<AgentToolCall>)collectedToolCalls;
                        var toolCallResult = await pipeline.RunAsync(outputContext, ct);
                        if (toolCallResult.IsBlocked)
                        {
                            var msg = await policy.ViolationHandler.HandleViolationAsync(
                                toolCallResult.BlockingResult!, outputContext, ct);
                            var retractUpdate = new AgentResponseUpdate(ChatRole.Assistant, msg);
                            retractUpdate.AdditionalProperties ??= [];
                            retractUpdate.AdditionalProperties[GuardrailEventPropertyKey] =
                                StreamingGuardrailEvent.Replace(msg, toolCallResult.BlockingResult!, 0);
                            yield return retractUpdate;
                        }
                    }
                    break;
            }
        }
    }

    /// <summary>
    /// Extracts text from streaming updates while also collecting any <see cref="FunctionCallContent"/>
    /// tool calls into the provided list. This ensures tool calls are not lost during progressive streaming.
    /// </summary>
    private static async IAsyncEnumerable<string> ExtractTextAndToolCalls(
        IAsyncEnumerable<AgentResponseUpdate> updates,
        List<AgentToolCall> collectedToolCalls,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct = default)
    {
        await foreach (var update in updates.WithCancellation(ct))
        {
            // collect tool calls
            foreach (var fc in update.Contents.OfType<FunctionCallContent>())
            {
                var args = new Dictionary<string, string>();
                if (fc.Arguments is not null)
                {
                    foreach (var (key, value) in fc.Arguments)
                    {
                        args[key] = value?.ToString() ?? "";
                    }
                }
                collectedToolCalls.Add(new AgentToolCall
                {
                    ToolName = fc.Name ?? "",
                    Arguments = args
                });
            }

            // yield text chunks
            if (!string.IsNullOrEmpty(update.Text))
                yield return update.Text;
        }
    }
}
