using System.Diagnostics;
using System.Text;
using System.Text.Json;
using AgentGuard.AgentFramework.Workflows;
using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Builders;
using AgentGuard.Core.Guardrails;
using AgentGuard.Core.Rules.ToolCall;
using AgentGuard.Core.Rules.ToolResult;
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
        => builder.UseAgentGuard(policy, toolResultOptions: null, logger);

    /// <summary>
    /// Adds AgentGuard guardrails to the MAF agent pipeline using a pre-built policy and explicit
    /// tool-result middleware options.
    /// </summary>
    /// <remarks>
    /// When the policy contains a <see cref="ToolResultGuardrailRule"/> and
    /// <see cref="ToolResultMiddlewareOptions.Enabled"/> is true (the default), a function-invocation
    /// middleware is wired so tool results are inspected BEFORE being fed back to the LLM.
    /// Requires the inner agent to have a <c>FunctionInvokingChatClient</c> in its pipeline.
    /// </remarks>
    public static AIAgentBuilder UseAgentGuard(
        this AIAgentBuilder builder,
        IGuardrailPolicy policy,
        ToolResultMiddlewareOptions? toolResultOptions,
        ILogger<GuardrailPipeline>? logger = null)
    {
        var pipeline = new GuardrailPipeline(policy, logger ?? NullLogger<GuardrailPipeline>.Instance);

        var hasToolResultRule = policy.Rules.Any(r => r is ToolResultGuardrailRule);
        var trOptions = toolResultOptions ?? new ToolResultMiddlewareOptions();

        if (hasToolResultRule && trOptions.Enabled)
        {
            builder = WireToolResultMiddleware(builder, policy, trOptions, logger);
        }

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

    /// <summary>
    /// Wires a function-invocation middleware that intercepts each tool result and runs a filtered
    /// sub-pipeline (tool-result and PII/secrets rules) BEFORE the result is fed back to the LLM.
    /// Blocked results are replaced with a placeholder; sanitized results substitute the modified content.
    /// </summary>
    private static AIAgentBuilder WireToolResultMiddleware(
        AIAgentBuilder builder,
        IGuardrailPolicy policy,
        ToolResultMiddlewareOptions options,
        ILogger<GuardrailPipeline>? logger)
    {
        // build a sub-policy containing only the rules we want to run on tool results
        var filteredRules = policy.Rules
            .Where(r => r.Phase.HasFlag(GuardrailPhase.Output) && options.IncludeRuleOrders.Contains(r.Order))
            .ToList();

        if (filteredRules.Count == 0)
        {
            return builder;
        }

        var subPolicy = new GuardrailPolicy(
            name: $"{policy.Name}.tool-results",
            rules: filteredRules,
            violationHandler: policy.ViolationHandler);

        var subPipeline = new GuardrailPipeline(subPolicy, logger ?? NullLogger<GuardrailPipeline>.Instance);

        // Wrap with an agent factory that only applies the function-invocation middleware
        // when a FunctionInvokingChatClient is present. This avoids breaking agents that
        // don't support function calling (e.g. tests, custom AIAgent subclasses).
        return builder.Use((innerAgent, services) =>
        {
            if (innerAgent.GetService<FunctionInvokingChatClient>() is null)
                return innerAgent;

            var subBuilder = new AIAgentBuilder(innerAgent);
            subBuilder.Use(BuildFunctionMiddleware(subPipeline, options));
            return subBuilder.Build(services);
        });
    }

    private static Func<AIAgent, FunctionInvocationContext, Func<FunctionInvocationContext, CancellationToken, ValueTask<object?>>, CancellationToken, ValueTask<object?>>
        BuildFunctionMiddleware(GuardrailPipeline subPipeline, ToolResultMiddlewareOptions options)
    {
        return async (agent, ctx, next, ct) =>
        {
            var raw = await next(ctx, ct);
            var content = ToolResultToString(raw);

            if (string.IsNullOrEmpty(content))
            {
                return raw;
            }

            var entry = new ToolResultEntry
            {
                ToolName = ctx.Function.Name,
                Content = content
            };

            var subContext = new GuardrailContext
            {
                Text = content,
                Phase = GuardrailPhase.Output,
                Messages = ctx.Messages?.ToList(),
                AgentName = agent.Name
            };
            subContext.Properties[ToolResultGuardrailRule.ToolResultsKey] = new[] { entry };

            var result = await subPipeline.RunAsync(subContext, ct);

            if (result.IsBlocked)
            {
                if (options.HardFail)
                {
                    throw new GuardrailViolationException(
                        result.BlockingResult!,
                        GuardrailPhase.Output,
                        $"{agent.Name ?? "agent"}.tool-result.{ctx.Function.Name}");
                }

                return options.BlockedPlaceholder;
            }

            if (result.WasModified)
            {
                if (subContext.Properties.TryGetValue(ToolResultGuardrailRule.SanitizedResultsKey, out var sanitizedObj) &&
                    sanitizedObj is IReadOnlyList<ToolResultEntry> sanitized && sanitized.Count > 0)
                {
                    return sanitized[0].Content;
                }

                return result.FinalText;
            }

            return raw;
        };
    }

    /// <summary>
    /// Converts a tool result <see cref="object"/> into a string for guardrail evaluation.
    /// Strings are passed through; complex objects are JSON-serialized.
    /// </summary>
    private static string ToolResultToString(object? raw)
    {
        if (raw is null)
            return "";
        if (raw is string s)
            return s;
        try
        {
            return JsonSerializer.Serialize(raw);
        }
        catch
        {
            return raw.ToString() ?? "";
        }
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

        // safety-net: extract any tool results that landed in the response messages
        // (covers tools that bypass FunctionInvokingChatClient — e.g. hosted tools, MCP)
        var toolResults = ExtractToolResults(response.Messages);

        // nothing to evaluate if no text, tool calls, or tool results
        if (string.IsNullOrEmpty(responseText) && toolCalls.Count == 0 && toolResults.Count == 0)
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

        if (toolResults.Count > 0)
            outputContext.Properties[ToolResultGuardrailRule.ToolResultsKey] = toolResults;

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
    /// Extracts <see cref="ToolResultEntry"/> instances from MAF response messages by reading
    /// <see cref="FunctionResultContent"/> items embedded in the message contents. Used as a
    /// post-hoc safety net for tool implementations that bypass <c>FunctionInvokingChatClient</c>
    /// (hosted tools, MCP). Pre-execution interception via the function-invocation middleware
    /// is preferred because it can prevent injection from reaching the LLM in the first place.
    /// </summary>
    private static List<ToolResultEntry> ExtractToolResults(IEnumerable<ChatMessage> responseMessages)
    {
        var materialized = responseMessages as IList<ChatMessage> ?? responseMessages.ToList();
        var callIdToName = BuildCallIdToToolNameMap(materialized.SelectMany(m => m.Contents));
        var results = new List<ToolResultEntry>();

        foreach (var message in materialized)
        {
            foreach (var fr in message.Contents.OfType<FunctionResultContent>())
            {
                AppendResult(results, fr, callIdToName);
            }
        }

        return results;
    }

    /// <summary>
    /// Extracts <see cref="ToolResultEntry"/> instances from streaming response updates.
    /// </summary>
    private static List<ToolResultEntry> ExtractToolResultsFromUpdates(IEnumerable<AgentResponseUpdate> updates)
    {
        var materialized = updates as IList<AgentResponseUpdate> ?? updates.ToList();
        var callIdToName = BuildCallIdToToolNameMap(materialized.SelectMany(u => u.Contents));
        var results = new List<ToolResultEntry>();

        foreach (var update in materialized)
        {
            foreach (var fr in update.Contents.OfType<FunctionResultContent>())
            {
                AppendResult(results, fr, callIdToName);
            }
        }

        return results;
    }

    private static Dictionary<string, string> BuildCallIdToToolNameMap(IEnumerable<AIContent> contents)
    {
        var map = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var fc in contents.OfType<FunctionCallContent>())
        {
            if (!string.IsNullOrEmpty(fc.CallId) && !string.IsNullOrEmpty(fc.Name))
                map[fc.CallId] = fc.Name;
        }
        return map;
    }

    private static void AppendResult(
        List<ToolResultEntry> results,
        FunctionResultContent fr,
        Dictionary<string, string> callIdToName)
    {
        var content = fr.Result switch
        {
            null => "",
            string s => s,
            var other => SafeSerialize(other)
        };

        if (string.IsNullOrEmpty(content))
            return;

        var toolName = (fr.CallId is not null && callIdToName.TryGetValue(fr.CallId, out var name))
            ? name
            : (fr.CallId ?? "unknown");

        results.Add(new ToolResultEntry
        {
            ToolName = toolName,
            Content = content
        });
    }

    private static string SafeSerialize(object value)
    {
        try { return JsonSerializer.Serialize(value); }
        catch { return value.ToString() ?? ""; }
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
        var toolResults = ExtractToolResultsFromUpdates(chunks);

        // run output guardrails on the accumulated text and/or tool calls
        if (!string.IsNullOrEmpty(fullText) || toolCalls.Count > 0 || toolResults.Count > 0)
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

            if (toolResults.Count > 0)
                outputContext.Properties[ToolResultGuardrailRule.ToolResultsKey] = toolResults;

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

        // collect tool calls and tool results from streaming updates alongside text extraction.
        // both are evaluated after the stream completes (FinalOnly semantics).
        var collectedToolCalls = new List<AgentToolCall>();
        var collectedCallIdToName = new Dictionary<string, string>(StringComparer.Ordinal);
        var collectedToolResults = new List<FunctionResultContent>();
        var textStream = ExtractTextAndToolCalls(
            innerAgent.RunStreamingAsync(processedMessages, session, options, ct),
            collectedToolCalls, collectedCallIdToName, collectedToolResults, ct);

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
                    // after stream completes, evaluate any collected tool calls and tool results
                    if (collectedToolCalls.Count > 0 || collectedToolResults.Count > 0)
                    {
                        if (collectedToolCalls.Count > 0)
                            outputContext.Properties[ToolCallGuardrailRule.ToolCallsKey] = (IReadOnlyList<AgentToolCall>)collectedToolCalls;

                        if (collectedToolResults.Count > 0)
                        {
                            var toolResults = new List<ToolResultEntry>(collectedToolResults.Count);
                            foreach (var fr in collectedToolResults)
                                AppendResult(toolResults, fr, collectedCallIdToName);
                            if (toolResults.Count > 0)
                                outputContext.Properties[ToolResultGuardrailRule.ToolResultsKey] = (IReadOnlyList<ToolResultEntry>)toolResults;
                        }

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
    /// tool calls and <see cref="FunctionResultContent"/> tool results into the provided lists.
    /// </summary>
    private static async IAsyncEnumerable<string> ExtractTextAndToolCalls(
        IAsyncEnumerable<AgentResponseUpdate> updates,
        List<AgentToolCall> collectedToolCalls,
        Dictionary<string, string> collectedCallIdToName,
        List<FunctionResultContent> collectedToolResults,
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

                if (!string.IsNullOrEmpty(fc.CallId) && !string.IsNullOrEmpty(fc.Name))
                    collectedCallIdToName[fc.CallId] = fc.Name;
            }

            // collect tool results
            foreach (var fr in update.Contents.OfType<FunctionResultContent>())
            {
                collectedToolResults.Add(fr);
            }

            // yield text chunks
            if (!string.IsNullOrEmpty(update.Text))
                yield return update.Text;
        }
    }
}
