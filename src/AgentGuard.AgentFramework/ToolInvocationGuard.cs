using System.Runtime.CompilerServices;
using System.Text.Json;
using AgentGuard.AgentFramework.Workflows;
using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Guardrails;
using AgentGuard.Core.Rules.ToolCall;
using AgentGuard.Core.Rules.ToolResult;
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;

namespace AgentGuard.AgentFramework;

/// <summary>
/// The tool interception behind <c>UseAgentGuard()</c>: a function-invocation middleware that checks
/// each call's arguments before the tool runs and each result before it goes back to the model, and
/// the run wrapper that stops the run on a <see cref="ToolResultMiddlewareOptions.HardFail"/> violation.
/// </summary>
internal static class ToolInvocationGuard
{
    /// <summary>The result given to a call that was not run because a violation stopped the run.</summary>
    internal const string NotRunPlaceholder = "[not run: a guardrail violation stopped the run]";

    // the HardFail run the current tool invocation belongs to, established by the run wrapper
    private static readonly AsyncLocal<HardFailRun?> CurrentRun = new();

    /// <summary>
    /// Creates the function-invocation middleware. Blocked calls and results are replaced with a
    /// placeholder; sanitized results substitute the modified content.
    /// </summary>
    internal static Func<AIAgent, FunctionInvocationContext, Func<FunctionInvocationContext, CancellationToken, ValueTask<object?>>, CancellationToken, ValueTask<object?>>
        CreateMiddleware(
            GuardrailPipeline? toolCallPipeline,
            GuardrailPipeline? textPipeline,
            GuardrailPipeline? toolResultPipeline,
            ToolResultMiddlewareOptions options)
    {
        return async (agent, ctx, next, ct) =>
        {
            // with concurrent invocation, calls of the same turn can start after a violation stopped the run
            if (options.HardFail && CurrentRun.Value is { Violation: not null })
            {
                ctx.Terminate = true;
                return NotRunPlaceholder;
            }

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

    /// <summary>
    /// Runs the agent for a policy with <see cref="ToolResultMiddlewareOptions.HardFail"/> and throws the
    /// violation the tool middleware recorded, once the run has returned.
    /// </summary>
    internal static async Task<AgentResponse> RunAsync(
        IEnumerable<ChatMessage> messages,
        AgentSession? session,
        AgentRunOptions? options,
        AIAgent innerAgent,
        CancellationToken cancellationToken)
    {
        var run = new HardFailRun();
        CurrentRun.Value = run;

        var response = await innerAgent.RunAsync(messages, session, run.Decorate(options), cancellationToken);

        run.ThrowIfViolated();
        return response;
    }

    /// <summary>The streaming form of <see cref="RunAsync"/>: the violation ends the enumeration.</summary>
    internal static async IAsyncEnumerable<AgentResponseUpdate> RunStreamingAsync(
        IEnumerable<ChatMessage> messages,
        AgentSession? session,
        AgentRunOptions? options,
        AIAgent innerAgent,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var run = new HardFailRun();
        var runOptions = run.Decorate(options);

        await using var updates = innerAgent.RunStreamingAsync(messages, session, runOptions, cancellationToken)
            .GetAsyncEnumerator(cancellationToken);

        while (true)
        {
            // a value set in an async iterator does not flow past its yield, so the run is established
            // again before each step of the inner stream
            CurrentRun.Value = run;
            if (!await updates.MoveNextAsync())
                break;

            yield return updates.Current;
        }

        run.ThrowIfViolated();
    }

    private static string Blocked(
        AIAgent agent,
        FunctionInvocationContext ctx,
        ToolResultMiddlewareOptions options,
        GuardrailPipelineResult result,
        string placeholder,
        string kind)
    {
        if (!options.HardFail)
            return placeholder;

        var violation = new GuardrailViolationException(
            result.BlockingResult!,
            GuardrailPhase.Output,
            $"{agent.Name ?? "agent"}.{kind}.{ctx.Function.Name}");

        // FunctionInvokingChatClient turns an exception thrown from here into an error result and calls
        // the model again, so the run is stopped with Terminate and the run wrapper throws the violation
        // once the run has returned. Invoked outside such a run, throwing is all that is left.
        if (CurrentRun.Value is not { } run)
            throw violation;

        run.Record(violation);
        ctx.Terminate = true;
        return placeholder;
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

    // one per run: the tool middleware records a violation here, the run wrapper throws it
    private sealed class HardFailRun
    {
        private GuardrailViolationException? _violation;

        public GuardrailViolationException? Violation => Volatile.Read(ref _violation);

        // concurrent calls can each be blocked; the first violation is the one reported
        public void Record(GuardrailViolationException violation) =>
            Interlocked.CompareExchange(ref _violation, violation, null);

        public void ThrowIfViolated()
        {
            if (Violation is { } violation)
                throw violation;
        }

        // the agent saves the run's messages to its session before this wrapper gets them back, so the
        // calls a stopped run leaves unanswered are answered in its chat client pipeline, which the
        // run options can extend
        public AgentRunOptions? Decorate(AgentRunOptions? options)
        {
            ChatClientAgentRunOptions runOptions;

            if (options is null)
            {
                runOptions = new ChatClientAgentRunOptions();
            }
            else if (options is ChatClientAgentRunOptions chatClientOptions)
            {
                runOptions = (ChatClientAgentRunOptions)chatClientOptions.Clone();
            }
            else if (options.GetType() == typeof(AgentRunOptions))
            {
                runOptions = new ChatClientAgentRunOptions
                {
                    ResponseFormat = options.ResponseFormat,
                    AllowBackgroundResponses = options.AllowBackgroundResponses,
#pragma warning disable MEAI001 // a background run's continuation token has to reach the agent unchanged
                    ContinuationToken = options.ContinuationToken,
#pragma warning restore MEAI001
                    AdditionalProperties = options.AdditionalProperties?.Clone()
                };
            }
            else
            {
                // the function-invocation middleware rejects other option types itself
                return options;
            }

            var factory = runOptions.ChatClientFactory;
            runOptions.ChatClientFactory = client =>
                new UnansweredCallsChatClient(factory is null ? client : factory(client), this);

            return runOptions;
        }
    }

    // FunctionInvokingChatClient stops at the call that ended the run, so the calls the model made in
    // the same turn after it get no result. Once a violation stopped the run, this answers them, so the
    // history the agent saves has no call without a result.
    private sealed class UnansweredCallsChatClient(IChatClient innerClient, HardFailRun run) : DelegatingChatClient(innerClient)
    {
        public override async Task<ChatResponse> GetResponseAsync(
            IEnumerable<ChatMessage> messages,
            ChatOptions? options = null,
            CancellationToken cancellationToken = default)
        {
            var response = await base.GetResponseAsync(messages, options, cancellationToken);

            if (run.Violation is not null && NotRunResults(response.Messages.SelectMany(m => m.Contents)) is { Count: > 0 } results)
                response.Messages.Add(new ChatMessage(ChatRole.Tool, results));

            return response;
        }

        public override async IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(
            IEnumerable<ChatMessage> messages,
            ChatOptions? options = null,
            [EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            var calls = new List<AIContent>();
            ChatResponseUpdate? last = null;

            await foreach (var update in base.GetStreamingResponseAsync(messages, options, cancellationToken))
            {
                calls.AddRange(update.Contents.Where(content => content is FunctionCallContent or FunctionResultContent));
                last = update;
                yield return update;
            }

            if (run.Violation is not null && NotRunResults(calls) is { Count: > 0 } results)
            {
                yield return new ChatResponseUpdate(ChatRole.Tool, results)
                {
                    ResponseId = last?.ResponseId,
                    ConversationId = last?.ConversationId
                };
            }
        }

        // FunctionInvokingChatClient marks every call it processed as informational
        private static List<AIContent> NotRunResults(IEnumerable<AIContent> contents)
        {
            var items = contents.ToList();
            var answered = items.OfType<FunctionResultContent>()
                .Select(result => result.CallId)
                .ToHashSet(StringComparer.Ordinal);

            return
            [
                .. items.OfType<FunctionCallContent>()
                    .Where(call => !call.InformationalOnly && !answered.Contains(call.CallId))
                    .Select(call => new FunctionResultContent(call.CallId, NotRunPlaceholder))
            ];
        }
    }
}
