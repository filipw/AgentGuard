using System.Diagnostics;
using System.Text;
using System.Text.Json;
using AgentGuard.AgentFramework.Workflows;
using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Builders;
using AgentGuard.Core.Guardrails;
using AgentGuard.Core.Ledger;
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
    /// tool-result middleware options.
    /// </summary>
    /// <param name="builder">The agent builder.</param>
    /// <param name="policy">The policy to enforce.</param>
    /// <param name="toolResultOptions">Tool-result interception options, or null for the defaults.</param>
    /// <param name="logger">Optional logger for the pipeline.</param>
    /// <param name="ledger">
    /// Optional decision ledger. When omitted, one registered in DI is resolved automatically, so
    /// <c>AddAgentGuard(o =&gt; o.UseDecisionLedger(...))</c> reaches the middleware's own pipeline.
    /// </param>
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
        ILogger<GuardrailPipeline>? logger = null,
        IGuardrailLedger? ledger = null)
    {
        var hasToolResultRule = policy.Rules.Any(r => r is ToolResultGuardrailRule);
        var trOptions = toolResultOptions ?? new ToolResultMiddlewareOptions();

        if (hasToolResultRule && trOptions.Enabled)
        {
            builder = WireToolResultMiddleware(builder, policy, trOptions, logger, ledger);
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

            var guarded = new AIAgentBuilder(innerAgent);
            guarded.Use(
                runFunc: async (messages, session, options, inner, ct) =>
                {
                    // materialize once: the caller may hand us a lazily-produced sequence, and the
                    // guardrail path used to enumerate it five times (which throws on a one-shot one).
                    var messageList = messages as IReadOnlyList<ChatMessage> ?? messages.ToList();

                    var (blocked, processedMessages) = await RunInputGuardrails(pipeline, policy, messageList, inner.Name, ct);
                    if (blocked is not null)
                        return blocked;

                    var response = await inner.RunAsync(processedMessages, session, options, ct);

                    return await RunOutputGuardrails(pipeline, policy, response, processedMessages, inner.Name, ct);
                },
                runStreamingFunc: (messages, session, options, inner, ct) =>
                {
                    var messageList = messages as IReadOnlyList<ChatMessage> ?? messages.ToList();
                    return StreamWithGuardrails(pipeline, policy, messageList, session, options, inner, ct);
                });

            return guarded.Build(services);
        });
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
        ILogger<GuardrailPipeline>? logger,
        IGuardrailLedger? ledger)
    {
        // the sub-policy is split in two. The text rules (PII, secrets, LLM PII) rewrite the tool
        // result; the tool-result rule then inspects what they produced. Running them in one pass
        // meant the tool-result rule sanitized the *original* entry from the property bag, and the
        // middleware preferred that output - throwing away the PII redaction that had just run.
        var included = policy.Rules
            .Where(r => r.Phase.HasFlag(GuardrailPhase.Output) && options.IncludeRuleOrders.Contains(r.Order))
            .ToList();

        var textRules = included.Where(r => r is not ToolResultGuardrailRule).ToList();
        var toolResultRules = included.Where(r => r is ToolResultGuardrailRule).ToList();

        if (included.Count == 0)
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
                Build(textRules, "tool-results.text"),
                Build(toolResultRules, "tool-results"),
                options));
            return subBuilder.Build(services);
        });
    }

    private static Func<AIAgent, FunctionInvocationContext, Func<FunctionInvocationContext, CancellationToken, ValueTask<object?>>, CancellationToken, ValueTask<object?>>
        BuildFunctionMiddleware(
            GuardrailPipeline? textPipeline,
            GuardrailPipeline? toolResultPipeline,
            ToolResultMiddlewareOptions options)
    {
        return async (agent, ctx, next, ct) =>
        {
            var raw = await next(ctx, ct);
            var content = ToolResultToString(raw);

            if (string.IsNullOrEmpty(content))
            {
                return raw;
            }

            var messages = ctx.Messages?.ToList();
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
                    return Blocked(agent, ctx, options, textResult);

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
                trContext.Properties[ToolResultGuardrailRule.ToolResultsKey] = new[] { entry };

                var trResult = await toolResultPipeline.RunAsync(trContext, ct);
                if (trResult.IsBlocked)
                    return Blocked(agent, ctx, options, trResult);

                if (trResult.WasModified &&
                    trContext.Properties.TryGetValue(ToolResultGuardrailRule.SanitizedResultsKey, out var sanitizedObj) &&
                    sanitizedObj is IReadOnlyList<ToolResultEntry> sanitized && sanitized.Count > 0)
                {
                    content = sanitized[0].Content;
                    changed = true;
                }
            }

            return changed ? content : raw;
        };
    }

    private static string Blocked(
        AIAgent agent, FunctionInvocationContext ctx, ToolResultMiddlewareOptions options, GuardrailPipelineResult result)
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

    private static async Task<(AgentResponse? blocked, IReadOnlyList<ChatMessage> messages)> RunInputGuardrails(
        GuardrailPipeline pipeline,
        IGuardrailPolicy policy,
        IReadOnlyList<ChatMessage> messages,
        string? agentName,
        CancellationToken ct)
    {
        using var inputActivity = AgentGuardTelemetry.ActivitySource.StartActivity(
            AgentGuardTelemetry.Spans.MiddlewareInput);

        inputActivity?.SetTag(AgentGuardTelemetry.Tags.AgentName, agentName);
        inputActivity?.SetTag(AgentGuardTelemetry.Tags.Phase, "input");

        // the last *user* message, not simply the last one. Taking whatever came last meant a
        // trailing assistant message was evaluated as untrusted user input, and it disagreed with
        // GuardrailChatClient, which has always used the last user message.
        var lastMessage = messages.LastOrDefault(m => m.Role == ChatRole.User);
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
            Messages = messages,
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
            modified[modified.LastIndexOf(lastMessage)] = new ChatMessage(lastMessage.Role, inputResult.FinalText);
            return (null, modified);
        }

        inputActivity?.SetTag(AgentGuardTelemetry.Tags.Outcome, AgentGuardTelemetry.Outcomes.Passed);
        return (null, messages);
    }

    private static async Task<AgentResponse> RunOutputGuardrails(
        GuardrailPipeline pipeline,
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

        var responseText = response.Messages
            .Where(m => m.Role == ChatRole.Assistant)
            .Select(m => m.Text)
            .LastOrDefault() ?? "";

        // extract tool calls from the response for ToolCallGuardrailRule
        var toolCalls = ExtractToolCalls(response.Messages);
        outputActivity?.SetTag(AgentGuardTelemetry.Tags.ToolCallCount, toolCalls.Count);

        // safety-net: extract any tool results that landed in the response messages
        // (covers tools that bypass FunctionInvokingChatClient - e.g. hosted tools, MCP)
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
            Messages = messages,
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
            return ReplaceText(response, msg, keepOtherContent: false);
        }

        if (outputResult.WasModified)
        {
            outputActivity?.SetTag(AgentGuardTelemetry.Tags.Outcome, AgentGuardTelemetry.Outcomes.Modified);
            return ReplaceText(response, outputResult.FinalText, keepOtherContent: true);
        }

        outputActivity?.SetTag(AgentGuardTelemetry.Tags.Outcome, AgentGuardTelemetry.Outcomes.Passed);
        return response;
    }

    /// <summary>
    /// Rebuilds a response around new assistant text while keeping the response-level metadata
    /// (id, agent id, usage, created-at) and, for a modification, the non-text content such as
    /// function calls. A bare <c>new AgentResponse([...])</c> discarded all of it, so a PII
    /// redaction on a tool-calling turn used to erase the tool calls and break the agent loop.
    /// </summary>
    private static AgentResponse ReplaceText(AgentResponse response, string text, bool keepOtherContent)
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

        return new AgentResponse(messages)
        {
            ResponseId = response.ResponseId,
            AgentId = response.AgentId,
            CreatedAt = response.CreatedAt,
            Usage = response.Usage,
            AdditionalProperties = response.AdditionalProperties
        };
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
        IReadOnlyList<ChatMessage> messages,
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
        IReadOnlyList<ChatMessage> processedMessages,
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
                Messages = processedMessages,
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
        IReadOnlyList<ChatMessage> processedMessages,
        AgentSession? session,
        AgentRunOptions? options,
        AIAgent innerAgent,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
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
