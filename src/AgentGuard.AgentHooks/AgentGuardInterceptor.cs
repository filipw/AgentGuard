using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Nodes;
using AgentGuard.AgentFramework;
using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Guardrails;
using AgentGuard.Core.Rules.ToolCall;
using AgentGuard.Core.Telemetry;
using AgentHooks;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.Logging.Abstractions;

namespace AgentGuard.AgentHooks;

/// <summary>
/// An Agent-Hooks (AGENT-HOOKS-0.1) interceptor that enforces an AgentGuard policy. It can be registered
/// with any Agent-Hooks host; for the Microsoft Agent Framework,
/// <see cref="AgentGuardAgentHooksExtensions"/> builds an agent with it installed.
/// </summary>
/// <remarks>
/// <para>
/// What each interception point checks:
/// <list type="bullet">
/// <item><description><c>input</c> - the input rules, over every user message of the request, as the other
/// integrations guard a request.</description></item>
/// <item><description><c>pre_model_call</c> - with <see cref="AgentGuardInterceptorOptions.GuardModelInput"/>,
/// the user and system messages of each model request, each distinct text judged once.</description></item>
/// <item><description><c>post_model_call</c> - the calls and results of tools the model service ran itself,
/// which the host never runs; and, with <see cref="ToolCallBlocking.StopRun"/>, the tool calls the response
/// asks the host to run, before any of them runs.</description></item>
/// <item><description><c>pre_tool_call</c> - with <see cref="ToolCallBlocking.ContinueWithToolError"/> (the
/// default), each tool call's arguments, before the tool runs.</description></item>
/// <item><description><c>post_tool_call</c> - when the policy has a tool-result rule, each result: the text
/// rules (PII, secrets) rewrite it, then the tool-result rule inspects it.</description></item>
/// <item><description><c>output</c> - the output rules, over each message of the response and its reasoning.
/// The tool calls and results in it were checked at the points above.</description></item>
/// </list>
/// </para>
/// <para>
/// A pass is an allow. A rewrite is a transform of the point's whole target (<c>$target</c>), in which the
/// messages the rules left alone are unchanged. A block is a deny with <c>rule:</c> and <c>severity:</c>
/// result labels. At the tool points the host passes the deny on to the model, so its reason is
/// <c>agentguard:blocked</c> and its message the neutral text the model receives in place of the call or
/// result; elsewhere the reason is <c>agentguard:&lt;rule&gt;</c> and the message is the policy's violation
/// message. Every evaluation is recorded to the ledger, when one is configured, with the
/// interception point as its stage.
/// </para>
/// <para>
/// The interceptor is safe to share across agents and concurrent runs.
/// </para>
/// </remarks>
public sealed class AgentGuardInterceptor : IInterceptor
{
    // runs whose conversation is kept for the output and tool checks at a time
    private const int HistoryCapacity = 1024;

    private readonly IGuardrailPolicy _policy;
    private readonly AgentGuardInterceptorOptions _options;
    private readonly ChatMessageGuard _inputGuard;
    private readonly ChatMessageGuard _requestGuard;
    private readonly ChatMessageGuard _outputGuard;
    private readonly ToolRulePipelines _tools;
    private readonly RequestHistoryCache _history = new(HistoryCapacity);

    /// <summary>Initializes a new instance of the <see cref="AgentGuardInterceptor"/> class.</summary>
    /// <param name="policy">The policy to enforce. The interceptor doesn't dispose it.</param>
    /// <param name="options">Where tool calls are checked, model-input checks, the ledger and so on. Defaults when null.</param>
    public AgentGuardInterceptor(IGuardrailPolicy policy, AgentGuardInterceptorOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(policy);

        _policy = policy;
        _options = options ?? new AgentGuardInterceptorOptions();

        var logger = _options.Logger ?? NullLogger<GuardrailPipeline>.Instance;

        // one guard, so a verdict reached for a message at one point is reused at the next
        var guard = new ChatMessageGuard(policy, logger, _options.Ledger);
        _inputGuard = guard.WithStage(InterceptionPoint.Input.ToWireName());
        _requestGuard = guard.WithStage(InterceptionPoint.PreModelCall.ToWireName());
        // the response's tool calls and results were checked at the tool points already: a call blocked
        // there never ran, and output must not block the answer the model gave after it
        _outputGuard = guard.WithStage(InterceptionPoint.Output.ToWireName()).WithoutToolContent();
        _tools = ToolRulePipelines.Create(policy, _options.ToolResultRuleOrders, logger, _options.Ledger);
    }

    /// <summary>The policy the interceptor enforces.</summary>
    public IGuardrailPolicy Policy => _policy;

    /// <inheritdoc />
    public async ValueTask<Verdict> InterceptAsync(AgentContext context, CancellationToken ct)
    {
        var point = context.InterceptionPoint;
        var agentName = StringOf(context.Json["agent"]?["name"]);

        using var activity = AgentGuardTelemetry.ActivitySource.StartActivity($"{AgentGuardTelemetry.Spans.Hooks}.{point.ToWireName()}");
        activity?.SetTag(AgentGuardTelemetry.Tags.InterceptionPoint, point.ToWireName());
        activity?.SetTag(AgentGuardTelemetry.Tags.PolicyName, _policy.Name);
        if (agentName is not null)
            activity?.SetTag(AgentGuardTelemetry.Tags.AgentName, agentName);

        try
        {
            var evaluation = point switch
            {
                InterceptionPoint.Input => await GuardInputAsync(context, agentName, ct).ConfigureAwait(false),
                InterceptionPoint.PreModelCall => await GuardModelRequestAsync(context, agentName, ct).ConfigureAwait(false),
                InterceptionPoint.PostModelCall => await GuardModelResponseAsync(context, agentName, ct).ConfigureAwait(false),
                InterceptionPoint.PreToolCall => await GuardToolCallAsync(context, agentName, ct).ConfigureAwait(false),
                InterceptionPoint.PostToolCall => await GuardToolResultAsync(context, agentName, ct).ConfigureAwait(false),
                InterceptionPoint.Output => await GuardOutputAsync(context, agentName, ct).ConfigureAwait(false),
                InterceptionPoint.AgentShutdown => EndSession(context),
                _ => Evaluation.Allow
            };

            activity?.SetTag(AgentGuardTelemetry.Tags.Outcome, evaluation.Outcome);
            if (evaluation.Blocking is { } blocking)
            {
                activity?.SetTag(AgentGuardTelemetry.Tags.BlockedReason, blocking.Reason);
                activity?.SetTag(AgentGuardTelemetry.Tags.Severity, blocking.Severity.ToString().ToLowerInvariant());

                // a block is an expected outcome; a rule that couldn't reach a verdict and failed closed is a failure
                if (blocking.IsError)
                    activity?.SetStatus(ActivityStatusCode.Error, blocking.Reason);
            }

            return evaluation.Verdict;
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            // the host turns the exception into a fail-closed deny; the span records it as a failure
            activity?.SetTag(AgentGuardTelemetry.Tags.ErrorType, ex.GetType().FullName);
            activity?.SetStatus(ActivityStatusCode.Error, ex.Message);
            throw;
        }
    }

    private async ValueTask<Evaluation> GuardInputAsync(AgentContext context, string? agentName, CancellationToken ct)
    {
        // a new run starts from its next model request
        if (SessionIdOf(context) is { } sessionId)
            _history.Remove(sessionId);

        if (context.Json["target"] is not JsonObject target)
            return Evaluation.Allow;

        var content = target["content"];
        var role = HookMessages.RoleOf(target);

        // one message arrives as its content; several as a list of { role, content } messages
        List<ChatMessage> messages;
        List<JsonObject>? sources = null;
        if (content is JsonArray array && IsMessageList(array))
            (messages, sources) = HookMessages.ReadMessages(array);
        else
            messages = [new ChatMessage(new ChatRole(role), HookMessages.ReadContents(content))];

        var result = await _inputGuard.GuardInputAsync(messages, agentName, ct).ConfigureAwait(false);
        if (result.IsBlocked)
            return await DenyAsync(result.BlockingResult!, result.BlockingContext!, InterceptionPoint.Input, ct).ConfigureAwait(false);

        if (!result.WasModified)
            return Evaluation.Allow;

        var newContent = sources is null
            ? HookMessages.WriteContents(result.Messages[0].Contents)
            : HookMessages.WriteMessages(result.Messages, messages, sources);

        return Transform(new JsonObject { ["content"] = newContent, ["role"] = role });
    }

    private async ValueTask<Evaluation> GuardModelRequestAsync(AgentContext context, string? agentName, CancellationToken ct)
    {
        if (context.Json["target"] is not JsonArray target)
            return Evaluation.Allow;

        var (messages, sources) = HookMessages.ReadMessages(target);
        var sessionId = SessionIdOf(context);

        if (!_options.GuardModelInput)
        {
            if (sessionId is not null)
                _history.TryAdd(sessionId, messages);

            return Evaluation.Allow;
        }

        var result = await _requestGuard.GuardRequestAsync(messages, agentName, ct).ConfigureAwait(false);
        if (sessionId is not null)
            _history.TryAdd(sessionId, result.Messages);

        return result.WasModified
            ? Transform(HookMessages.WriteMessages(result.Messages, messages, sources))
            : Evaluation.Allow;
    }

    private async ValueTask<Evaluation> GuardModelResponseAsync(AgentContext context, string? agentName, CancellationToken ct)
    {
        if (context.Json["target"] is not JsonObject target)
            return Evaluation.Allow;

        // tools the model service ran itself come back in the response's content, calls and results
        // together; the host never runs them, so this is the first point that sees them
        List<AIContent> serviceContents = target["content"] is JsonArray content && IsMessageList(content)
            ? [.. HookMessages.ReadMessages(content).Messages.SelectMany(m => m.Contents)]
            : [];

        var calls = GuardrailChatContent.ExtractToolCalls(serviceContents);
        var results = _tools.ChecksResults ? GuardrailChatContent.ExtractToolResults(serviceContents) : [];

        // with StopRun, the calls the host is about to run are checked here, all of them before any runs
        if (_options.ToolCallBlocking == ToolCallBlocking.StopRun && target["tool_calls"] is JsonArray toolCalls)
        {
            calls.AddRange(toolCalls.OfType<JsonObject>().Select(call =>
                GuardrailChatContent.ToToolCall(StringOf(call["name"]) ?? "", ArgumentsOf(call["args"]))));
        }

        if (calls.Count == 0 && results.Count == 0)
            return Evaluation.Allow;

        var history = HistoryOf(context);
        var stage = InterceptionPoint.PostModelCall.ToWireName();
        var blocked = await _tools.CheckCallsAsync(calls, history, agentName, stage, ct).ConfigureAwait(false);

        // the model has used a service-run result already, so a rewrite can't reach it: only a block counts
        foreach (var result in results)
        {
            if (blocked is not null)
                break;

            var check = await _tools.CheckResultAsync(result.ToolName, result.Content, history, agentName, stage, ct).ConfigureAwait(false);
            blocked = check.Blocking;
        }

        if (blocked is null)
            return Evaluation.Allow;

        // the run ends here, so the caller is told why
        var handlerContext = new GuardrailContext { Text = "", Phase = GuardrailPhase.Output, Messages = history, AgentName = agentName, Stage = stage };
        return await DenyAsync(blocked.BlockingResult!, handlerContext, InterceptionPoint.PostModelCall, ct).ConfigureAwait(false);
    }

    private async ValueTask<Evaluation> GuardToolCallAsync(AgentContext context, string? agentName, CancellationToken ct)
    {
        if (_options.ToolCallBlocking != ToolCallBlocking.ContinueWithToolError)
            return Evaluation.Allow;

        var name = StringOf(context.Json["tool_call"]?["name"]) ?? "";
        var call = GuardrailChatContent.ToToolCall(name, ArgumentsOf(context.Json["target"]));

        var blocked = await _tools.CheckCallsAsync(
            [call], HistoryOf(context), agentName, InterceptionPoint.PreToolCall.ToWireName(), ct).ConfigureAwait(false);

        // the model gets the message as the call's error and carries on
        return blocked is null
            ? Evaluation.Allow
            : Deny(blocked.BlockingResult!, _options.BlockedToolCallMessage, InterceptionPoint.PreToolCall);
    }

    private async ValueTask<Evaluation> GuardToolResultAsync(AgentContext context, string? agentName, CancellationToken ct)
    {
        if (!_tools.ChecksResults)
            return Evaluation.Allow;

        var target = context.Json["target"];

        // the rules evaluate the text the tool returned, not its JSON encoding
        var content = GuardrailChatContent.ToText(target);
        if (string.IsNullOrEmpty(content))
            return Evaluation.Allow;

        var name = StringOf(context.Json["tool_call"]?["name"]) ?? "";
        var check = await _tools.CheckResultAsync(
            name, content, HistoryOf(context), agentName, InterceptionPoint.PostToolCall.ToWireName(), ct).ConfigureAwait(false);

        if (check.IsBlocked)
            return Deny(check.Blocking!.BlockingResult!, _options.BlockedToolResultMessage, InterceptionPoint.PostToolCall);

        return check.Content is { } rewritten ? Transform(RestoreShape(target, rewritten)) : Evaluation.Allow;
    }

    private async ValueTask<Evaluation> GuardOutputAsync(AgentContext context, string? agentName, CancellationToken ct)
    {
        if (context.Json["target"] is not JsonObject target)
            return Evaluation.Allow;

        var content = target["content"];

        // a response of one plain-text message arrives as that text; any other as a list of messages
        List<ChatMessage> messages;
        List<JsonObject> sources;
        var plainText = !(content is JsonArray array && IsMessageList(array));
        if (plainText)
        {
            var message = new ChatMessage(ChatRole.Assistant, HookMessages.ReadContents(content));
            messages = [message];
            sources = [HookMessages.WriteMessage(message)];
        }
        else
        {
            (messages, sources) = HookMessages.ReadMessages((JsonArray)content!);
        }

        var result = await _outputGuard.GuardOutputAsync(messages, HistoryOf(context), agentName, ct).ConfigureAwait(false);
        if (result.IsBlocked)
            return await DenyAsync(result.BlockingResult!, result.BlockingContext!, InterceptionPoint.Output, ct).ConfigureAwait(false);

        if (!result.WasModified)
            return Evaluation.Allow;

        // plain text stays plain text; anything else goes back as a list the host matches to its messages
        JsonNode newContent = plainText && result.Messages is [{ Contents: [TextContent text] }]
            ? JsonValue.Create(text.Text ?? string.Empty)
            : HookMessages.WriteMessages(result.Messages, messages, sources);

        return Transform(new JsonObject { ["content"] = newContent });
    }

    private Evaluation EndSession(AgentContext context)
    {
        if (SessionIdOf(context) is { } sessionId)
            _history.Remove(sessionId);

        return Evaluation.Allow;
    }

    private async ValueTask<Evaluation> DenyAsync(
        GuardrailResult blocking, GuardrailContext context, InterceptionPoint point, CancellationToken ct)
    {
        var message = await _policy.ViolationHandler.HandleViolationAsync(blocking, context, ct).ConfigureAwait(false);
        return Deny(blocking, message, point);
    }

    private Evaluation Deny(GuardrailResult blocking, string message, InterceptionPoint point)
    {
        var rule = string.IsNullOrEmpty(blocking.RuleName) ? "policy" : blocking.RuleName;

        // at the tool points the host passes the reason on to the model, so there it doesn't name the rule
        var reason = point is InterceptionPoint.PreToolCall or InterceptionPoint.PostToolCall
            ? "agentguard:blocked"
            : $"agentguard:{rule}";

        var verdict = _options.EscalateWhen?.Invoke(blocking, point) == true
            ? Verdict.Escalate(reason, message)
            : Verdict.Deny(reason, message);

        verdict = verdict with
        {
            ResultLabels = [$"rule:{rule}", $"severity:{blocking.Severity.ToString().ToLowerInvariant()}"]
        };

        return new Evaluation(verdict, AgentGuardTelemetry.Outcomes.Blocked, blocking);
    }

    private Evaluation Transform(JsonNode target) =>
        new(
            Verdict.Allow with
            {
                Decision = Decision.Transform,
                Reason = "agentguard:modified",
                Message = $"rewritten by AgentGuard policy '{_policy.Name}'",
                Transform = new Transform("$target", target)
            },
            AgentGuardTelemetry.Outcomes.Modified,
            null);

    // a rewritten JSON object or array goes back as JSON, so the model doesn't get a quoted string
    private static JsonNode RestoreShape(JsonNode? original, string content)
    {
        if (original is JsonObject or JsonArray)
        {
            try
            {
                var parsed = JsonNode.Parse(content);
                if (parsed is JsonObject or JsonArray)
                    return parsed;
            }
            catch (JsonException)
            {
                // the rewritten text is not valid JSON (e.g. a whole line was removed): hand back the text
            }
        }

        return JsonValue.Create(content);
    }

    private IReadOnlyList<ChatMessage>? HistoryOf(AgentContext context) =>
        SessionIdOf(context) is { } sessionId ? _history.Get(sessionId) : null;

    private static string? SessionIdOf(AgentContext context) => StringOf(context.Json["session"]?["id"]);

    private static string? StringOf(JsonNode? node) =>
        node is JsonValue value && value.TryGetValue<string>(out var text) ? text : null;

    private static IEnumerable<KeyValuePair<string, object?>> ArgumentsOf(JsonNode? arguments) =>
        arguments is JsonObject values
            ? values.Select(pair => new KeyValuePair<string, object?>(pair.Key, pair.Value))
            : [];

    // the host sends several messages as { role, content } objects, one message as its content
    private static bool IsMessageList(JsonArray array) =>
        array.Count > 0 && array.All(item => item is JsonObject message && message.ContainsKey("content"));

    private readonly record struct Evaluation(Verdict Verdict, string Outcome, GuardrailResult? Blocking)
    {
        public static Evaluation Allow => new(Verdict.Allow, AgentGuardTelemetry.Outcomes.Passed, null);
    }
}
