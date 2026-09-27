using System.Diagnostics;
using System.Runtime.CompilerServices;
using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Builders;
using AgentGuard.Core.ChatClient;
using AgentGuard.Core.Guardrails;
using AgentGuard.Core.Ledger;
using AgentGuard.Core.Rules;
using AgentGuard.Core.Rules.ToolCall;
using AgentGuard.Core.Rules.ToolResult;
using AgentGuard.Core.Streaming;
using AgentGuard.Core.Telemetry;
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace AgentGuard.AgentFramework;

/// <summary>
/// Extension methods for integrating AgentGuard guardrails into the Microsoft Agent Framework pipeline.
/// </summary>
public static class AgentGuardMiddlewareExtensions
{
    /// <summary>
    /// Well-known key used in <see cref="AgentResponseUpdate.AdditionalProperties"/>
    /// to carry <see cref="StreamingGuardrailEvent"/> instances during progressive streaming.
    /// </summary>
    public const string GuardrailEventPropertyKey = "agentguard.event";

    /// <summary>
    /// Adds AgentGuard guardrails to the MAF agent pipeline using a fluent builder configuration.
    /// See <see cref="UseAgentGuard(AIAgentBuilder, IGuardrailPolicy, ToolResultMiddlewareOptions?, ILogger{GuardrailPipeline}?, IGuardrailLedger?)"/>
    /// for what is guarded and how.
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
    /// See <see cref="UseAgentGuard(AIAgentBuilder, IGuardrailPolicy, ToolResultMiddlewareOptions?, ILogger{GuardrailPipeline}?, IGuardrailLedger?)"/>
    /// for what is guarded and how.
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
    /// <para>
    /// Input guardrails run on every user message of the request and output guardrails on every
    /// assistant message of the response, its reasoning, and its tool calls and results (see
    /// <see cref="ChatMessageGuard"/>). A streamed response is buffered and guarded the same way, then
    /// replayed, rebuilt from the guarded messages when anything changed. With progressive streaming
    /// the text streams as it arrives and retraction/replacement events (under
    /// <see cref="GuardrailEventPropertyKey"/>) correct it, while everything else - tool calls and
    /// results, reasoning, usage, finish reason - is held back until the stream has passed its final
    /// check, and dropped if it ends blocked.
    /// </para>
    /// <para>
    /// When the policy contains a <see cref="ToolCallGuardrailRule"/> or a <see cref="ToolResultGuardrailRule"/>
    /// (gated with <c>.When()</c>/<c>.Unless()</c> or not) and <see cref="ToolResultMiddlewareOptions.Enabled"/>
    /// is true (the default), a function-invocation middleware is wired: each tool call's arguments are
    /// checked BEFORE the tool runs, and each tool result is inspected BEFORE it is fed back to the LLM.
    /// Requires the inner agent to have a <c>FunctionInvokingChatClient</c> in its pipeline.
    /// </para>
    /// <para>
    /// A <c>ChatClientAgent</c> saves each response to its session before this middleware sees it. When
    /// an output guardrail blocks or rewrites the response, the middleware puts what the caller received
    /// in its place, so the next turn does not replay unguarded output to the model. That works for the
    /// default <see cref="InMemoryChatHistoryProvider"/> in a run with a session and no server-side
    /// conversation (<see cref="ChatClientAgentSession.ConversationId"/>). With other chat history
    /// providers, or a conversation the service stores, the saved history keeps the unguarded response;
    /// when it must never hold unguarded output, guard the agent's <see cref="IChatClient"/> instead
    /// (<see cref="GuardrailChatClientExtensions.UseAgentGuard(IChatClient, IGuardrailPolicy, ILogger{GuardrailPipeline}?, IGuardrailLedger?)"/>):
    /// the <see cref="GuardrailChatClient"/> decorator runs before the agent saves the response, except
    /// for progressive streaming, which delivers text before it is checked.
    /// </para>
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

        // the guard is built inside the agent factory so the service provider is in scope: that is
        // what lets a ledger registered with AddAgentGuard reach this pipeline without the caller
        // threading it through by hand.
        return builder.Use((innerAgent, services) =>
        {
            var guard = new ChatMessageGuard(policy, logger, ledger ?? services?.GetService<IGuardrailLedger>());

            var guarded = new AIAgentBuilder(innerAgent);
            guarded.Use(
                runFunc: (messages, session, options, inner, ct) =>
                    RunWithGuardrailsAsync(guard, policy, Materialize(messages), session, options, inner, ct),
                runStreamingFunc: (messages, session, options, inner, ct) =>
                    StreamWithGuardrails(guard, policy, Materialize(messages), session, options, inner, ct));

            return guarded.Build(services);
        });
    }

    // the caller may hand over a lazily-produced sequence that can only be enumerated once
    private static IReadOnlyList<ChatMessage> Materialize(IEnumerable<ChatMessage> messages) =>
        messages as IReadOnlyList<ChatMessage> ?? messages.ToList();

    /// <summary>
    /// Wires a function-invocation middleware that checks each tool call's arguments before the tool
    /// runs, and runs a filtered sub-pipeline (tool-result and PII/secrets rules) on each tool result
    /// BEFORE the result is fed back to the LLM.
    /// </summary>
    private static AIAgentBuilder WireToolMiddleware(
        AIAgentBuilder builder,
        IGuardrailPolicy policy,
        ToolResultMiddlewareOptions options,
        ILogger<GuardrailPipeline>? logger,
        IGuardrailLedger? ledger)
    {
        if (!ToolRulePipelines.Applies(policy, options.IncludeRuleOrders))
        {
            return builder;
        }

        return builder.Use((innerAgent, services) =>
        {
            if (innerAgent.GetService<FunctionInvokingChatClient>() is null)
                return innerAgent;

            var pipelines = ToolRulePipelines.Create(
                policy,
                options.IncludeRuleOrders,
                logger ?? NullLogger<GuardrailPipeline>.Instance,
                ledger ?? services?.GetService<IGuardrailLedger>());

            var subBuilder = new AIAgentBuilder(innerAgent);

            // FunctionInvokingChatClient swallows exceptions thrown by function middleware, so a HardFail
            // violation stops the run from inside and this wrapper throws it once the run has returned
            if (options.HardFail)
                subBuilder.Use(ToolInvocationGuard.RunAsync, ToolInvocationGuard.RunStreamingAsync);

            subBuilder.Use(ToolInvocationGuard.CreateMiddleware(pipelines, options));
            return subBuilder.Build(services);
        });
    }

    private static async Task<AgentResponse> RunWithGuardrailsAsync(
        ChatMessageGuard guard,
        IGuardrailPolicy policy,
        IReadOnlyList<ChatMessage> messages,
        AgentSession? session,
        AgentRunOptions? options,
        AIAgent inner,
        CancellationToken ct)
    {
        var input = await RunInputGuardrails(guard, policy, messages, inner.Name, ct);
        if (input.Result.IsBlocked)
            return new AgentResponse([new ChatMessage(ChatRole.Assistant, input.ViolationMessage)]);

        var response = await inner.RunAsync(input.Result.Messages, session, options, ct);

        var responseMessages = response.Messages as IReadOnlyList<ChatMessage> ?? [.. response.Messages];
        var output = await RunOutputGuardrails(guard, policy, responseMessages, input.Result.Messages, inner.Name, ct);

        AgentResponse guarded;
        if (output.Result.IsBlocked)
        {
            // a blocked response must not carry any of the original content through
            guarded = WithMessages(response, [new ChatMessage(ChatRole.Assistant, output.ViolationMessage)], blocked: true);
        }
        else if (output.Result.WasModified)
        {
            guarded = WithMessages(response, [.. output.Result.Messages], blocked: false);
        }
        else
        {
            return response;
        }

        // the response the agent saved is the very list it returned, so the saved messages are found by reference
        SessionHistoryRewriter.ReplaceSavedResponse(
            inner, session, (response.RawRepresentation as ChatResponse)?.ConversationId,
            responseMessages, [.. guarded.Messages], matchByReference: true);

        return guarded;
    }

    private static async Task<Verdict> RunInputGuardrails(
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

        try
        {
            // every user message is guarded: a client may send the whole transcript (AG-UI does), and
            // every message in it reaches the model
            var result = await guard.GuardInputAsync(messages, agentName, ct);
            return await ConcludeAsync(inputActivity, policy, result, ct);
        }
        catch (Exception ex)
        {
            RecordFailure(inputActivity, ex);
            throw;
        }
    }

    private static async Task<Verdict> RunOutputGuardrails(
        ChatMessageGuard guard,
        IGuardrailPolicy policy,
        IReadOnlyList<ChatMessage> responseMessages,
        IReadOnlyList<ChatMessage> requestMessages,
        string? agentName,
        CancellationToken ct)
    {
        using var outputActivity = AgentGuardTelemetry.ActivitySource.StartActivity(
            AgentGuardTelemetry.Spans.MiddlewareOutput);

        outputActivity?.SetTag(AgentGuardTelemetry.Tags.AgentName, agentName);
        outputActivity?.SetTag(AgentGuardTelemetry.Tags.Phase, "output");
        outputActivity?.SetTag(AgentGuardTelemetry.Tags.ToolCallCount,
            responseMessages.SelectMany(m => m.Contents).OfType<FunctionCallContent>().Count());

        try
        {
            // every assistant message is checked on its own - the text a model writes alongside a tool
            // call is shown to the user too - together with the response's tool calls and, as a safety
            // net for tools that bypass FunctionInvokingChatClient (hosted tools, MCP), its tool results
            var result = await guard.GuardOutputAsync(responseMessages, requestMessages, agentName, ct);
            return await ConcludeAsync(outputActivity, policy, result, ct);
        }
        catch (Exception ex)
        {
            RecordFailure(outputActivity, ex);
            throw;
        }
    }

    private static async Task<Verdict> ConcludeAsync(
        Activity? activity, IGuardrailPolicy policy, ChatMessageGuardResult result, CancellationToken ct)
    {
        if (!result.IsBlocked)
        {
            activity?.SetTag(AgentGuardTelemetry.Tags.Outcome,
                result.WasModified ? AgentGuardTelemetry.Outcomes.Modified : AgentGuardTelemetry.Outcomes.Passed);
            return new Verdict(result, "");
        }

        RecordBlock(activity, result.BlockingResult);
        var message = await policy.ViolationHandler.HandleViolationAsync(result.BlockingResult!, result.BlockingContext!, ct);
        return new Verdict(result, message);
    }

    // a block is an expected policy outcome, recorded by the outcome tag and not as a span error; a rule
    // that could not reach a verdict and failed closed is a real failure
    private static void RecordBlock(Activity? activity, GuardrailResult? blockingResult)
    {
        if (activity is null)
            return;

        activity.SetTag(AgentGuardTelemetry.Tags.Outcome, AgentGuardTelemetry.Outcomes.Blocked);

        if (blockingResult is null)
            return;

        activity.SetTag(AgentGuardTelemetry.Tags.BlockedReason, blockingResult.Reason);
        activity.SetTag(AgentGuardTelemetry.Tags.Severity, blockingResult.Severity.ToString().ToLowerInvariant());

        if (blockingResult.IsError)
            activity.SetStatus(ActivityStatusCode.Error, blockingResult.Reason);
    }

    // the caller's cancellation is not a failure of the guardrails
    private static void RecordFailure(Activity? activity, Exception exception)
    {
        if (activity is null || exception is OperationCanceledException)
            return;

        activity.SetTag(AgentGuardTelemetry.Tags.ErrorType, exception.GetType().FullName);
        activity.SetStatus(ActivityStatusCode.Error, exception.Message);
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

        var outcome = new StreamOutcome();
        await using var updates = GuardStream(guard, policy, messages, session, options, innerAgent, outcome, streamingActivity, ct)
            .GetAsyncEnumerator(ct);

        while (await MoveNextAsync(updates, streamingActivity))
            yield return updates.Current;

        outcome.Record(streamingActivity);
    }

    private static async ValueTask<bool> MoveNextAsync(IAsyncEnumerator<AgentResponseUpdate> updates, Activity? activity)
    {
        try
        {
            return await updates.MoveNextAsync();
        }
        catch (Exception ex)
        {
            RecordFailure(activity, ex);
            throw;
        }
    }

    private static async IAsyncEnumerable<AgentResponseUpdate> GuardStream(
        ChatMessageGuard guard,
        IGuardrailPolicy policy,
        IReadOnlyList<ChatMessage> messages,
        AgentSession? session,
        AgentRunOptions? options,
        AIAgent innerAgent,
        StreamOutcome outcome,
        Activity? streamingActivity,
        [EnumeratorCancellation] CancellationToken ct)
    {
        // input guardrails run before streaming
        var input = await RunInputGuardrails(guard, policy, messages, innerAgent.Name, ct);
        if (input.Result.IsBlocked)
        {
            outcome.Blocked(input.Result.BlockingResult);
            yield return new AgentResponseUpdate(ChatRole.Assistant, input.ViolationMessage);
            yield break;
        }

        var progressive = policy.ProgressiveStreaming is not null;
        streamingActivity?.SetTag(AgentGuardTelemetry.Tags.StreamingStrategy, progressive ? "progressive" : "buffered");

        var stream = progressive
            ? StreamWithProgressiveGuardrails(guard, policy, input.Result.Messages, session, options, innerAgent, outcome, ct)
            : StreamWithBufferedGuardrails(guard, policy, input.Result.Messages, session, options, innerAgent, outcome, ct);

        await foreach (var update in stream)
            yield return update;
    }

    private static async IAsyncEnumerable<AgentResponseUpdate> StreamWithBufferedGuardrails(
        ChatMessageGuard guard,
        IGuardrailPolicy policy,
        IReadOnlyList<ChatMessage> processedMessages,
        AgentSession? session,
        AgentRunOptions? options,
        AIAgent innerAgent,
        StreamOutcome outcome,
        [EnumeratorCancellation] CancellationToken ct)
    {
        var updates = new List<AgentResponseUpdate>();
        await foreach (var update in innerAgent.RunStreamingAsync(processedMessages, session, options, ct))
            updates.Add(update);

        // the buffered response is guarded exactly like a non-streamed one: message by message
        var agentResponse = updates.ToAgentResponse();
        var response = agentResponse.AsChatResponse();
        var saved = response.Messages as IReadOnlyList<ChatMessage> ?? [.. response.Messages];

        var output = await RunOutputGuardrails(guard, policy, saved, processedMessages, innerAgent.Name, ct);

        if (output.Result.IsBlocked)
        {
            outcome.Blocked(output.Result.BlockingResult);
            SessionHistoryRewriter.ReplaceSavedResponse(
                innerAgent, session, response.ConversationId, saved,
                [new ChatMessage(ChatRole.Assistant, output.ViolationMessage)], matchByReference: false);

            // a blocked response must not carry any of the original content through
            yield return ToAgentUpdate(new ChatResponseUpdate(ChatRole.Assistant, output.ViolationMessage)
            {
                ResponseId = response.ResponseId,
                ConversationId = response.ConversationId,
                ModelId = response.ModelId,
                CreatedAt = response.CreatedAt
            }, agentResponse.AgentId);
            yield break;
        }

        if (!output.Result.WasModified)
        {
            foreach (var update in updates)
                yield return update;
            yield break;
        }

        outcome.Modified();
        SessionHistoryRewriter.ReplaceSavedResponse(
            innerAgent, session, response.ConversationId, saved, output.Result.Messages, matchByReference: false);

        response.ContinuationToken = LastContinuationToken(updates);
        foreach (var update in GuardrailChatContent.ToUpdates(response, output.Result.Messages))
            yield return ToAgentUpdate(update, agentResponse.AgentId);
    }

    private static async IAsyncEnumerable<AgentResponseUpdate> StreamWithProgressiveGuardrails(
        ChatMessageGuard guard,
        IGuardrailPolicy policy,
        IReadOnlyList<ChatMessage> processedMessages,
        AgentSession? session,
        AgentRunOptions? options,
        AIAgent innerAgent,
        StreamOutcome outcome,
        [EnumeratorCancellation] CancellationToken ct)
    {
        var streamingPipeline = new StreamingGuardrailPipeline(policy, policy.ProgressiveStreaming, ledger: guard.Pipeline.Ledger);

        var outputContext = new GuardrailContext
        {
            Text = "", // will be set per-evaluation inside the pipeline
            Phase = GuardrailPhase.Output,
            Messages = processedMessages,
            AgentName = innerAgent.Name
        };

        var upstream = new ProgressiveUpstream();
        var textStream = upstream.ReadTextAsync(innerAgent.RunStreamingAsync(processedMessages, session, options, ct), ct);

        StreamingFinalResult? final = null;
        var shownLength = 0;

        await foreach (var output in streamingPipeline.ProcessStreamAsync(textStream, outputContext, policy.ViolationHandler, ct))
        {
            switch (output.Type)
            {
                case StreamingOutputType.TextChunk:
                    shownLength += output.Text!.Length;
                    yield return ToAgentUpdate(TextUpdate(output.Text, upstream.Current), upstream.Current?.AgentId);
                    break;

                case StreamingOutputType.GuardrailEvent:
                    if (output.GuardrailEvent!.Type == StreamingGuardrailEventType.Replacement)
                        shownLength = output.GuardrailEvent.ReplacementText?.Length ?? 0;
                    yield return EventUpdate(output.GuardrailEvent, upstream.Current);
                    break;

                case StreamingOutputType.Completed:
                    final = output.FinalResult;
                    break;
            }
        }

        // the response as the agent saved it
        var agentResponse = upstream.All.ToAgentResponse();
        var response = agentResponse.AsChatResponse();
        var saved = response.Messages as IReadOnlyList<ChatMessage> ?? [.. response.Messages];

        if (final is { IsBlocked: true })
        {
            // the retraction already replaced the text; what was held back goes with it
            outcome.Blocked(final.BlockingResult);
            SessionHistoryRewriter.ReplaceSavedResponse(
                innerAgent, session, response.ConversationId, saved,
                [new ChatMessage(ChatRole.Assistant, final.ReplacementText ?? "")], matchByReference: false);
            yield break;
        }

        // tool calls, tool results and reasoning were held back while the text streamed: check them now
        var result = await guard.GuardToolsAndReasoningAsync(saved, processedMessages, innerAgent.Name, ct);

        if (result.IsBlocked)
        {
            var msg = await policy.ViolationHandler.HandleViolationAsync(result.BlockingResult!, result.BlockingContext!, ct);

            outcome.Blocked(result.BlockingResult);
            SessionHistoryRewriter.ReplaceSavedResponse(
                innerAgent, session, response.ConversationId, saved,
                [new ChatMessage(ChatRole.Assistant, msg)], matchByReference: false);

            yield return EventUpdate(StreamingGuardrailEvent.Retract(result.BlockingResult!, shownLength), upstream.Current);
            yield return EventUpdate(StreamingGuardrailEvent.Replace(msg, result.BlockingResult!, shownLength), upstream.Current);
            yield break;
        }

        var rewrittenText = final is { WasModified: true } ? final.ReplacementText : null;
        if (rewrittenText is not null || result.WasModified)
        {
            // the caller now holds the rewritten text as one answer, plus the guarded rest of the response
            outcome.Modified();
            SessionHistoryRewriter.ReplaceSavedResponse(
                innerAgent, session, response.ConversationId, saved,
                rewrittenText is null ? result.Messages : GuardrailChatContent.ReplaceAnswer(result.Messages, rewrittenText),
                matchByReference: false);
        }

        if (!result.WasModified)
        {
            foreach (var update in upstream.Held)
                yield return update;
            yield break;
        }

        // the text has already been delivered, so only the rest of the guarded messages goes out
        response.ContinuationToken = LastContinuationToken(upstream.All);
        foreach (var update in GuardrailChatContent.ToUpdates(response, WithoutText(result.Messages)))
            yield return ToAgentUpdate(update, agentResponse.AgentId);
    }

    private static IEnumerable<ChatMessage> WithoutText(IEnumerable<ChatMessage> messages) =>
        messages
            .Select(message => string.IsNullOrEmpty(message.Text) ? message : GuardrailChatContent.WithText(message, ""))
            .Where(message => message.Contents.Count > 0 || message.AdditionalProperties is { Count: > 0 });

    private static ResponseContinuationToken? LastContinuationToken(List<AgentResponseUpdate> updates) =>
        updates.LastOrDefault(update => update.ContinuationToken is not null)?.ContinuationToken;

    // wrapped the way ChatClientAgent wraps its updates, so AsChatResponseUpdate() still yields the
    // conversation id and model, and nothing of the original content
    private static AgentResponseUpdate ToAgentUpdate(ChatResponseUpdate update, string? agentId) =>
        new(update) { AgentId = agentId };

    // a streamed chunk keeps the ids of the update it came from
    private static ChatResponseUpdate TextUpdate(string text, AgentResponseUpdate? source)
    {
        var raw = source?.RawRepresentation as ChatResponseUpdate;
        return new ChatResponseUpdate(source?.Role ?? ChatRole.Assistant, text)
        {
            AuthorName = source?.AuthorName,
            MessageId = source?.MessageId,
            ResponseId = source?.ResponseId,
            ConversationId = raw?.ConversationId,
            ModelId = raw?.ModelId,
            CreatedAt = source?.CreatedAt
        };
    }

    private static AgentResponseUpdate EventUpdate(StreamingGuardrailEvent guardrailEvent, AgentResponseUpdate? source)
    {
        var update = TextUpdate(guardrailEvent.ReplacementText ?? "", source);
        update.AdditionalProperties = new() { [GuardrailEventPropertyKey] = guardrailEvent };
        return ToAgentUpdate(update, source?.AgentId);
    }

    // everything but the text of an update, which is held back while its text streams
    private static AgentResponseUpdate WithoutText(AgentResponseUpdate update)
    {
        var raw = update.RawRepresentation as ChatResponseUpdate;
        return ToAgentUpdate(new ChatResponseUpdate(update.Role, GuardrailChatContent.ReplaceText(update.Contents, ""))
        {
            AuthorName = update.AuthorName,
            MessageId = update.MessageId,
            ResponseId = update.ResponseId,
            ConversationId = raw?.ConversationId,
            ModelId = raw?.ModelId,
            CreatedAt = update.CreatedAt,
            FinishReason = update.FinishReason,
            ContinuationToken = update.ContinuationToken,
            AdditionalProperties = update.AdditionalProperties
        }, update.AgentId);
    }

    // a guard's outcome, and the text the caller sees instead when it blocked
    private readonly record struct Verdict(ChatMessageGuardResult Result, string ViolationMessage);

    // the outcome a stream ended with, recorded on the streaming span once the stream is done
    private sealed class StreamOutcome
    {
        private string _outcome = AgentGuardTelemetry.Outcomes.Passed;
        private GuardrailResult? _blockingResult;

        public void Modified() => _outcome = AgentGuardTelemetry.Outcomes.Modified;

        public void Blocked(GuardrailResult? blockingResult)
        {
            _outcome = AgentGuardTelemetry.Outcomes.Blocked;
            _blockingResult = blockingResult;
        }

        public void Record(Activity? activity)
        {
            if (_outcome == AgentGuardTelemetry.Outcomes.Blocked)
                RecordBlock(activity, _blockingResult);
            else
                activity?.SetTag(AgentGuardTelemetry.Tags.Outcome, _outcome);
        }
    }

    // splits the upstream stream: its text goes to the streaming pipeline as it arrives, everything
    // else waits in Held until the stream has passed its final check
    private sealed class ProgressiveUpstream
    {
        public List<AgentResponseUpdate> All { get; } = [];

        public List<AgentResponseUpdate> Held { get; } = [];

        public AgentResponseUpdate? Current { get; private set; }

        public async IAsyncEnumerable<string> ReadTextAsync(
            IAsyncEnumerable<AgentResponseUpdate> updates,
            [EnumeratorCancellation] CancellationToken ct)
        {
            await foreach (var update in updates.WithCancellation(ct))
            {
                All.Add(update);
                Current = update;

                var text = update.Text;
                if (string.IsNullOrEmpty(text))
                {
                    Held.Add(update);
                    continue;
                }

                var rest = WithoutText(update);
                if (rest.Contents.Count > 0 || rest.FinishReason is not null ||
                    rest.ContinuationToken is not null || rest.AdditionalProperties is { Count: > 0 })
                {
                    Held.Add(rest);
                }

                yield return text;
            }
        }
    }
}
