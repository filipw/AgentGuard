using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using AgentGuard.AgentFramework.Workflows;
using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Builders;
using AgentGuard.Core.Guardrails;
using AgentGuard.Core.Ledger;
using AgentGuard.Core.Rules;
using AgentGuard.Core.Rules.ToolCall;
using AgentGuard.Core.Rules.ToolResult;
using AgentGuard.Core.Streaming;
using AgentGuard.Core.Telemetry;
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;
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
    /// <param name="builder">The agent builder.</param>
    /// <param name="configure">Configures the policy.</param>
    /// <param name="logger">Optional logger for the pipeline.</param>
    /// <param name="ledger">
    /// Optional decision ledger. When omitted, one registered in DI is resolved automatically.
    /// </param>
    public static AIAgentBuilder UseAgentGuard(
        this AIAgentBuilder builder,
        Action<GuardrailPolicyBuilder> configure,
        ILogger<GuardrailPipeline>? logger = null,
        IGuardrailLedger? ledger = null)
    {
        var policyBuilder = new GuardrailPolicyBuilder();
        configure(policyBuilder);
        return builder.UseAgentGuard(policyBuilder.Build(), toolResultOptions: null, logger, ledger);
    }

    /// <summary>
    /// Adds AgentGuard guardrails to the MAF agent pipeline using a pre-built policy.
    /// </summary>
    /// <param name="builder">The agent builder.</param>
    /// <param name="policy">The policy to enforce.</param>
    /// <param name="logger">Optional logger for the pipeline.</param>
    /// <param name="ledger">
    /// Optional decision ledger. When omitted, one registered in DI is resolved automatically.
    /// </param>
    public static AIAgentBuilder UseAgentGuard(
        this AIAgentBuilder builder, IGuardrailPolicy policy, ILogger<GuardrailPipeline>? logger = null,
        IGuardrailLedger? ledger = null)
        => builder.UseAgentGuard(policy, toolResultOptions: null, logger, ledger);

    /// <summary>
    /// Adds AgentGuard guardrails to the MAF agent pipeline using a pre-built policy and explicit
    /// tool middleware options.
    /// </summary>
    /// <param name="builder">The agent builder.</param>
    /// <param name="policy">The policy to enforce.</param>
    /// <param name="toolResultOptions">Tool call and tool result interception options, or null for the defaults.</param>
    /// <param name="logger">Optional logger for the pipeline.</param>
    /// <param name="ledger">
    /// Optional decision ledger. When omitted, one registered in DI is resolved automatically, so
    /// <c>AddAgentGuard(o =&gt; o.UseDecisionLedger(...))</c> reaches the middleware's own pipeline.
    /// </param>
    /// <remarks>
    /// When the policy contains a <see cref="ToolCallGuardrailRule"/> or a <see cref="ToolResultGuardrailRule"/>
    /// (gated with <c>.When()</c>/<c>.Unless()</c> or not) and <see cref="ToolResultMiddlewareOptions.Enabled"/>
    /// is true (the default), a function-invocation middleware is wired: each tool call's arguments are
    /// checked BEFORE the tool runs, and each tool result is inspected BEFORE it is fed back to the LLM.
    /// Requires the inner agent to have a <c>FunctionInvokingChatClient</c> in its pipeline.
    /// </remarks>
    public static AIAgentBuilder UseAgentGuard(
        this AIAgentBuilder builder,
        IGuardrailPolicy policy,
        ToolResultMiddlewareOptions? toolResultOptions,
        ILogger<GuardrailPipeline>? logger = null,
        IGuardrailLedger? ledger = null)
    {
        var hasToolRule = policy.Rules.Any(r => r.Unwrap() is ToolResultGuardrailRule or ToolCallGuardrailRule);
        var trOptions = toolResultOptions ?? new ToolResultMiddlewareOptions();

        if (hasToolRule && trOptions.Enabled)
        {
            builder = WireToolMiddleware(builder, policy, trOptions, logger, ledger);
        }

        // the pipeline is built inside the agent factory so the service provider is in scope: that
        // is what lets a ledger registered with AddAgentGuard reach this pipeline without the
        // caller threading it through by hand.
        return builder.Use((innerAgent, services) =>
        {
            var pipeline = new GuardrailPipeline(
                policy,
                logger ?? NullLogger<GuardrailPipeline>.Instance,
                ledger ?? services?.GetService<IGuardrailLedger>());
            var guard = new ChatMessageGuard(pipeline);

            var guarded = new AIAgentBuilder(innerAgent);
            guarded.Use(
                runFunc: async (messages, session, options, inner, ct) =>
                {
                    // materialize once: the caller may hand us a lazily-produced sequence that can only be
                    // enumerated once
                    var messageList = messages as IReadOnlyList<ChatMessage> ?? messages.ToList();

                    var (blocked, processedMessages) = await RunInputGuardrails(guard, policy, messageList, inner.Name, ct);
                    if (blocked is not null)
                        return blocked;

                    var response = await inner.RunAsync(processedMessages, session, options, ct);

                    return await RunOutputGuardrails(guard, policy, response, processedMessages, inner.Name, ct);
                },
                runStreamingFunc: (messages, session, options, inner, ct) =>
                {
                    var messageList = messages as IReadOnlyList<ChatMessage> ?? messages.ToList();
                    return StreamWithGuardrails(guard, pipeline, policy, messageList, session, options, inner, ct);
                });

            return guarded.Build(services);
        });
    }

    /// <summary>
    /// Wires a function-invocation middleware that checks each tool call's arguments before the tool
    /// runs, and runs a filtered sub-pipeline (tool-result and PII/secrets rules) on each tool result
    /// BEFORE the result is fed back to the LLM. Blocked calls and results are replaced with a
    /// placeholder; sanitized results substitute the modified content.
    /// </summary>
    private static AIAgentBuilder WireToolMiddleware(
        AIAgentBuilder builder,
        IGuardrailPolicy policy,
        ToolResultMiddlewareOptions options,
        ILogger<GuardrailPipeline>? logger,
        IGuardrailLedger? ledger)
    {
        // gated rules (.When/.Unless) are matched by what they wrap but still evaluated through the
        // gate, so their predicate keeps applying.
        var toolCallRules = policy.Rules.Where(r => r.Unwrap() is ToolCallGuardrailRule).ToList();

        // the result sub-policy is split in two: the text rules (PII, secrets, LLM PII) rewrite the
        // tool result, then the tool-result rule inspects what they produced
        var inspectResults = policy.Rules.Any(r => r.Unwrap() is ToolResultGuardrailRule);
        var included = inspectResults
            ? policy.Rules
                .Where(r => r.Phase.HasFlag(GuardrailPhase.Output) && options.IncludeRuleOrders.Contains(r.Order))
                .ToList()
            : [];

        var textRules = included.Where(r => r.Unwrap() is not (ToolResultGuardrailRule or ToolCallGuardrailRule)).ToList();
        var toolResultRules = included.Where(r => r.Unwrap() is ToolResultGuardrailRule).ToList();

        if (toolCallRules.Count == 0 && included.Count == 0)
        {
            return builder;
        }

        return builder.Use((innerAgent, services) =>
        {
            if (innerAgent.GetService<FunctionInvokingChatClient>() is null)
                return innerAgent;

            var effectiveLedger = ledger ?? services?.GetService<IGuardrailLedger>();
            var effectiveLogger = logger ?? NullLogger<GuardrailPipeline>.Instance;

            GuardrailPipeline? Build(List<IGuardrailRule> rules, string suffix) =>
                rules.Count == 0
                    ? null
                    : new GuardrailPipeline(
                        new GuardrailPolicy($"{policy.Name}.{suffix}", rules, policy.ViolationHandler),
                        effectiveLogger,
                        effectiveLedger);

            var subBuilder = new AIAgentBuilder(innerAgent);
            subBuilder.Use(BuildFunctionMiddleware(
                Build(toolCallRules, "tool-calls"),
                Build(textRules, "tool-results.text"),
                Build(toolResultRules, "tool-results"),
                options));
            return subBuilder.Build(services);
        });
    }

    private static Func<AIAgent, FunctionInvocationContext, Func<FunctionInvocationContext, CancellationToken, ValueTask<object?>>, CancellationToken, ValueTask<object?>>
        BuildFunctionMiddleware(
            GuardrailPipeline? toolCallPipeline,
            GuardrailPipeline? textPipeline,
            GuardrailPipeline? toolResultPipeline,
            ToolResultMiddlewareOptions options)
    {
        return async (agent, ctx, next, ct) =>
        {
            var messages = ctx.Messages?.ToList();

            // pass 0: the call's arguments, checked before the tool runs
            if (toolCallPipeline is not null)
            {
                var callContext = new GuardrailContext
                {
                    Text = "",
                    Phase = GuardrailPhase.Output,
                    Messages = messages,
                    AgentName = agent.Name
                };
                callContext.Properties[ToolCallGuardrailRule.ToolCallsKey] =
                    (IReadOnlyList<AgentToolCall>)[GuardrailChatContent.ToToolCall(ctx.Function.Name, ctx.Arguments)];

                var callResult = await toolCallPipeline.RunAsync(callContext, ct);
                if (callResult.IsBlocked)
                    return Blocked(agent, ctx, options, callResult, options.BlockedToolCallPlaceholder, "tool-call");
            }

            var raw = await next(ctx, ct);

            if (textPipeline is null && toolResultPipeline is null)
                return raw;

            // AIFunctionFactory tools return a JsonElement; the rules evaluate the text the tool returned,
            // not its JSON encoding
            var content = GuardrailChatContent.ToText(raw);

            if (string.IsNullOrEmpty(content))
            {
                return raw;
            }

            var changed = false;

            // pass 1: text rules rewrite the content in place
            if (textPipeline is not null)
            {
                var textContext = new GuardrailContext
                {
                    Text = content,
                    Phase = GuardrailPhase.Output,
                    Messages = messages,
                    AgentName = agent.Name
                };

                var textResult = await textPipeline.RunAsync(textContext, ct);
                if (textResult.IsBlocked)
                    return Blocked(agent, ctx, options, textResult, options.BlockedPlaceholder, "tool-result");

                if (textResult.WasModified)
                {
                    content = textResult.FinalText;
                    changed = true;
                }
            }

            // pass 2: the tool-result rule sees whatever pass 1 produced
            if (toolResultPipeline is not null)
            {
                var entry = new ToolResultEntry { ToolName = ctx.Function.Name, Content = content };
                var trContext = new GuardrailContext
                {
                    Text = content,
                    Phase = GuardrailPhase.Output,
                    Messages = messages,
                    AgentName = agent.Name
                };
                trContext.Properties[ToolResultGuardrailRule.ToolResultsKey] = (IReadOnlyList<ToolResultEntry>)[entry];

                var trResult = await toolResultPipeline.RunAsync(trContext, ct);
                if (trResult.IsBlocked)
                    return Blocked(agent, ctx, options, trResult, options.BlockedPlaceholder, "tool-result");

                // the rule hands cleaned content back through the property bag, not as FinalText (its
                // text is not the tool result), so WasModified never signals it
                if (trContext.Properties.TryGetValue(ToolResultGuardrailRule.SanitizedResultsKey, out var sanitizedObj) &&
                    sanitizedObj is IReadOnlyList<ToolResultEntry> { Count: > 0 } sanitized &&
                    !string.Equals(sanitized[0].Content, content, StringComparison.Ordinal))
                {
                    content = sanitized[0].Content;
                    changed = true;
                }
            }

            return changed ? RestoreShape(raw, content) : raw;
        };
    }

    // a rewritten JSON object or array goes back as JSON, so the model doesn't get a quoted string
    private static object RestoreShape(object? raw, string content)
    {
        if (raw is JsonElement { ValueKind: JsonValueKind.Object or JsonValueKind.Array })
        {
            try
            {
                using var document = JsonDocument.Parse(content);
                return document.RootElement.Clone();
            }
            catch (JsonException)
            {
                // the rewritten text is not valid JSON (e.g. a whole line was removed): hand back the text
            }
        }

        return content;
    }

    private static string Blocked(
        AIAgent agent,
        FunctionInvocationContext ctx,
        ToolResultMiddlewareOptions options,
        GuardrailPipelineResult result,
        string placeholder,
        string kind)
    {
        if (options.HardFail)
        {
            throw new GuardrailViolationException(
                result.BlockingResult!,
                GuardrailPhase.Output,
                $"{agent.Name ?? "agent"}.{kind}.{ctx.Function.Name}");
        }

        return placeholder;
    }

    private static async Task<(AgentResponse? blocked, IReadOnlyList<ChatMessage> messages)> RunInputGuardrails(
        ChatMessageGuard guard,
        IGuardrailPolicy policy,
        IReadOnlyList<ChatMessage> messages,
        string? agentName,
        CancellationToken ct)
    {
        using var inputActivity = AgentGuardTelemetry.ActivitySource.StartActivity(
            AgentGuardTelemetry.Spans.MiddlewareInput);

        inputActivity?.SetTag(AgentGuardTelemetry.Tags.AgentName, agentName);
        inputActivity?.SetTag(AgentGuardTelemetry.Tags.Phase, "input");

        // every user message is guarded: a client may send the whole transcript (AG-UI does), and every
        // message in it reaches the model
        var result = await guard.GuardInputAsync(messages, agentName, ct);

        if (result.IsBlocked)
        {
            inputActivity?.SetTag(AgentGuardTelemetry.Tags.Outcome, AgentGuardTelemetry.Outcomes.Blocked);
            inputActivity?.SetStatus(ActivityStatusCode.Error, result.BlockingResult?.Reason);
            var msg = await policy.ViolationHandler.HandleViolationAsync(result.BlockingResult!, result.BlockingContext!, ct);
            return (new AgentResponse([new ChatMessage(ChatRole.Assistant, msg)]), messages);
        }

        inputActivity?.SetTag(AgentGuardTelemetry.Tags.Outcome,
            result.WasModified ? AgentGuardTelemetry.Outcomes.Modified : AgentGuardTelemetry.Outcomes.Passed);
        return (null, result.Messages);
    }

    private static async Task<AgentResponse> RunOutputGuardrails(
        ChatMessageGuard guard,
        IGuardrailPolicy policy,
        AgentResponse response,
        IReadOnlyList<ChatMessage> messages,
        string? agentName,
        CancellationToken ct)
    {
        using var outputActivity = AgentGuardTelemetry.ActivitySource.StartActivity(
            AgentGuardTelemetry.Spans.MiddlewareOutput);

        outputActivity?.SetTag(AgentGuardTelemetry.Tags.AgentName, agentName);
        outputActivity?.SetTag(AgentGuardTelemetry.Tags.Phase, "output");
        outputActivity?.SetTag(AgentGuardTelemetry.Tags.ToolCallCount,
            response.Messages.SelectMany(m => m.Contents).OfType<FunctionCallContent>().Count());

        // every assistant message is checked on its own - the text a model writes alongside a tool
        // call is shown to the user too - together with the response's tool calls and, as a safety
        // net for tools that bypass FunctionInvokingChatClient (hosted tools, MCP), its tool results
        var responseMessages = response.Messages as IReadOnlyList<ChatMessage> ?? [.. response.Messages];
        var result = await guard.GuardOutputAsync(responseMessages, messages, agentName, ct);

        if (result.IsBlocked)
        {
            outputActivity?.SetTag(AgentGuardTelemetry.Tags.Outcome, AgentGuardTelemetry.Outcomes.Blocked);
            outputActivity?.SetStatus(ActivityStatusCode.Error, result.BlockingResult?.Reason);
            var msg = await policy.ViolationHandler.HandleViolationAsync(result.BlockingResult!, result.BlockingContext!, ct);

            // a blocked response must not carry any of the original content through
            return WithMessages(response, [new ChatMessage(ChatRole.Assistant, msg)], blocked: true);
        }

        if (result.WasModified)
        {
            outputActivity?.SetTag(AgentGuardTelemetry.Tags.Outcome, AgentGuardTelemetry.Outcomes.Modified);
            return WithMessages(response, [.. result.Messages], blocked: false);
        }

        outputActivity?.SetTag(AgentGuardTelemetry.Tags.Outcome, AgentGuardTelemetry.Outcomes.Passed);
        return response;
    }

    /// <summary>
    /// Rebuilds a response around new messages while keeping the response-level metadata (id, agent
    /// id, usage, created-at, finish reason).
    /// </summary>
    private static AgentResponse WithMessages(AgentResponse response, IList<ChatMessage> messages, bool blocked) =>
        new(messages)
        {
            ResponseId = response.ResponseId,
            AgentId = response.AgentId,
            CreatedAt = response.CreatedAt,
            Usage = response.Usage,
            FinishReason = blocked ? null : response.FinishReason,
            AdditionalProperties = response.AdditionalProperties
        };

    private static async IAsyncEnumerable<AgentResponseUpdate> StreamWithGuardrails(
        ChatMessageGuard guard,
        GuardrailPipeline pipeline,
        IGuardrailPolicy policy,
        IReadOnlyList<ChatMessage> messages,
        AgentSession? session,
        AgentRunOptions? options,
        AIAgent innerAgent,
        [EnumeratorCancellation] CancellationToken ct)
    {
        using var streamingActivity = AgentGuardTelemetry.ActivitySource.StartActivity(
            AgentGuardTelemetry.Spans.MiddlewareStreaming);

        streamingActivity?.SetTag(AgentGuardTelemetry.Tags.AgentName, innerAgent.Name);

        // run input guardrails before streaming
        var (blocked, processedMessages) = await RunInputGuardrails(guard, policy, messages, innerAgent.Name, ct);
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
        IReadOnlyList<ChatMessage> processedMessages,
        AgentSession? session,
        AgentRunOptions? options,
        AIAgent innerAgent,
        [EnumeratorCancellation] CancellationToken ct)
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

        // extract tool calls and tool results from the streaming chunks
        var contents = chunks.SelectMany(c => c.Contents).ToList();
        var toolCalls = GuardrailChatContent.ExtractToolCalls(contents);
        var toolResults = GuardrailChatContent.ExtractToolResults(contents);

        // run output guardrails on the accumulated text and/or tool calls
        if (!string.IsNullOrEmpty(fullText) || toolCalls.Count > 0 || toolResults.Count > 0)
        {
            var outputContext = new GuardrailContext
            {
                Text = fullText,
                Phase = GuardrailPhase.Output,
                Messages = processedMessages,
                AgentName = innerAgent.Name
            };

            AddToolProperties(outputContext, toolCalls, toolResults);

            var outputResult = await pipeline.RunAsync(outputContext, ct);

            if (outputResult.IsBlocked)
            {
                var msg = await policy.ViolationHandler.HandleViolationAsync(outputResult.BlockingResult!, outputContext, ct);
                yield return new AgentResponseUpdate(ChatRole.Assistant, msg);
                yield break;
            }

            if (outputResult.WasModified)
            {
                foreach (var update in ReplaceStreamedText(chunks, outputResult.FinalText))
                    yield return update;
                yield break;
            }
        }

        // output passed guardrails - yield all original chunks
        foreach (var chunk in chunks)
        {
            yield return chunk;
        }
    }

    // the rewritten text goes out as one update, followed by everything else the stream carried -
    // function calls, approval requests, usage, ids - so a rewrite doesn't break the agent loop
    private static IEnumerable<AgentResponseUpdate> ReplaceStreamedText(List<AgentResponseUpdate> chunks, string text)
    {
        var template = chunks.FirstOrDefault(c => !string.IsNullOrEmpty(c.Text));

        yield return new AgentResponseUpdate(template?.Role ?? ChatRole.Assistant, text)
        {
            AuthorName = template?.AuthorName,
            AgentId = template?.AgentId,
            MessageId = template?.MessageId,
            ResponseId = template?.ResponseId,
            CreatedAt = template?.CreatedAt
        };

        foreach (var chunk in chunks)
        {
            var rest = GuardrailChatContent.ReplaceText(chunk.Contents, "");
            if (rest.Count == 0 && chunk.FinishReason is null && chunk.ContinuationToken is null)
                continue;

            yield return new AgentResponseUpdate(chunk.Role, rest)
            {
                AuthorName = chunk.AuthorName,
                AgentId = chunk.AgentId,
                MessageId = chunk.MessageId,
                ResponseId = chunk.ResponseId,
                CreatedAt = chunk.CreatedAt,
                FinishReason = chunk.FinishReason,
                ContinuationToken = chunk.ContinuationToken,
                AdditionalProperties = chunk.AdditionalProperties
            };
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
        IReadOnlyList<ChatMessage> processedMessages,
        AgentSession? session,
        AgentRunOptions? options,
        AIAgent innerAgent,
        [EnumeratorCancellation] CancellationToken ct)
    {
        var streamingPipeline = new StreamingGuardrailPipeline(policy, policy.ProgressiveStreaming, ledger: pipeline.Ledger);

        var outputContext = new GuardrailContext
        {
            Text = "", // will be set per-evaluation inside the pipeline
            Phase = GuardrailPhase.Output,
            Messages = processedMessages,
            AgentName = innerAgent.Name
        };

        // collect tool calls and tool results from streaming updates alongside text extraction.
        // both are evaluated after the stream completes (FinalOnly semantics).
        var collected = new List<AIContent>();
        var textStream = ExtractTextAndToolContent(
            innerAgent.RunStreamingAsync(processedMessages, session, options, ct), collected, ct);

        var shownLength = 0;

        await foreach (var output in streamingPipeline.ProcessStreamAsync(textStream, outputContext, policy.ViolationHandler, ct))
        {
            switch (output.Type)
            {
                case StreamingOutputType.TextChunk:
                    shownLength += output.Text?.Length ?? 0;
                    yield return new AgentResponseUpdate(ChatRole.Assistant, output.Text);
                    break;

                case StreamingOutputType.GuardrailEvent:
                    if (output.GuardrailEvent?.Type == StreamingGuardrailEventType.Replacement)
                        shownLength = output.GuardrailEvent.ReplacementText?.Length ?? 0;
                    yield return EventUpdate(output.GuardrailEvent!);
                    break;

                case StreamingOutputType.Completed:
                    // after stream completes, evaluate any collected tool calls and tool results
                    var toolCalls = GuardrailChatContent.ExtractToolCalls(collected);
                    var toolResults = GuardrailChatContent.ExtractToolResults(collected);
                    if (toolCalls.Count == 0 && toolResults.Count == 0)
                        break;

                    AddToolProperties(outputContext, toolCalls, toolResults);

                    var toolCallResult = await pipeline.RunAsync(outputContext, ct);
                    if (toolCallResult.IsBlocked)
                    {
                        var msg = await policy.ViolationHandler.HandleViolationAsync(
                            toolCallResult.BlockingResult!, outputContext, ct);
                        yield return EventUpdate(StreamingGuardrailEvent.Retract(toolCallResult.BlockingResult!, shownLength));
                        yield return EventUpdate(StreamingGuardrailEvent.Replace(msg, toolCallResult.BlockingResult!, shownLength));
                    }
                    break;
            }
        }
    }

    private static AgentResponseUpdate EventUpdate(StreamingGuardrailEvent guardrailEvent)
    {
        var update = new AgentResponseUpdate(ChatRole.Assistant, guardrailEvent.ReplacementText ?? "");
        update.AdditionalProperties ??= [];
        update.AdditionalProperties[GuardrailEventPropertyKey] = guardrailEvent;
        return update;
    }

    /// <summary>
    /// Extracts text from streaming updates while collecting any <see cref="FunctionCallContent"/>
    /// tool calls and <see cref="FunctionResultContent"/> tool results into <paramref name="collected"/>.
    /// </summary>
    private static async IAsyncEnumerable<string> ExtractTextAndToolContent(
        IAsyncEnumerable<AgentResponseUpdate> updates,
        List<AIContent> collected,
        [EnumeratorCancellation] CancellationToken ct = default)
    {
        await foreach (var update in updates.WithCancellation(ct))
        {
            collected.AddRange(update.Contents.Where(c => c is FunctionCallContent or FunctionResultContent));

            // yield text chunks
            if (!string.IsNullOrEmpty(update.Text))
                yield return update.Text;
        }
    }

    private static void AddToolProperties(
        GuardrailContext context, List<AgentToolCall> toolCalls, List<ToolResultEntry> toolResults)
    {
        if (toolCalls.Count > 0)
            context.Properties[ToolCallGuardrailRule.ToolCallsKey] = (IReadOnlyList<AgentToolCall>)toolCalls;

        if (toolResults.Count > 0)
            context.Properties[ToolResultGuardrailRule.ToolResultsKey] = (IReadOnlyList<ToolResultEntry>)toolResults;
    }
}
