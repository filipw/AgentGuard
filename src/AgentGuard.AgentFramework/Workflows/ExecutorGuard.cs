using System.Diagnostics;
using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Guardrails;
using AgentGuard.Core.Telemetry;
using Microsoft.Agents.AI;
using Microsoft.Agents.AI.Workflows;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.Logging;

namespace AgentGuard.AgentFramework.Workflows;

/// <summary>
/// Runs a guarded executor's guardrail policy over workflow messages and applies the verdict: a block
/// throws <see cref="GuardrailViolationException"/>, a rewrite is applied to the message. Shared by both
/// <c>GuardedExecutor</c> variants.
/// </summary>
/// <remarks>
/// Chat payloads are guarded without the <see cref="ITextExtractor"/>. A <see cref="ChatMessage"/> has its
/// text checked and rewritten in place. A message collection or an <see cref="AgentResponse"/> goes
/// through the <see cref="ChatMessageGuard"/> the way the agent middleware guards a request (on the way in)
/// or a response (on the way out), and the newest message with text is checked whatever its role. Every
/// other message goes through the extractor.
/// </remarks>
internal sealed class ExecutorGuard
{
    private readonly string _executorId;
    private readonly ChatMessageGuard _chatGuard;
    private readonly ITextExtractor _textExtractor;
    private readonly ILogger? _log;

    public ExecutorGuard(string executorId, IGuardrailPolicy policy, GuardedExecutorOptions? options)
    {
        _executorId = executorId;
        _textExtractor = options?.TextExtractor ?? DefaultTextExtractor.Instance;
        _log = options?.Logger;

        // one guard per executor: its pipeline evaluates every message the executor sees, and it keeps the
        // verdicts reached for the earlier messages of a conversation
        _chatGuard = new ChatMessageGuard(policy, _log is null ? null : new LoggerWrapper(_log), options?.Ledger);
    }

    /// <summary>
    /// Guards a message and returns the one to continue with: the original, or a copy with the policy's
    /// rewrite applied.
    /// </summary>
    /// <param name="message">The message.</param>
    /// <param name="messageType">The type the executor declares for the message; a rebuilt message must be one.</param>
    /// <param name="phase">Input for a message on its way in, output for an executor's result.</param>
    /// <param name="spanName">The name of the span that records the verdict.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The message to continue with.</returns>
    /// <exception cref="GuardrailViolationException">The policy blocked the message.</exception>
    public async ValueTask<object?> GuardAsync(
        object? message, Type messageType, GuardrailPhase phase, string spanName, CancellationToken cancellationToken)
    {
        using var activity = AgentGuardTelemetry.ActivitySource.StartActivity(spanName);
        activity?.SetTag(AgentGuardTelemetry.Tags.ExecutorId, _executorId);
        activity?.SetTag(AgentGuardTelemetry.Tags.Phase, phase == GuardrailPhase.Input ? "input" : "output");
        activity?.SetTag(AgentGuardTelemetry.Tags.MessageType, messageType.Name);

        Verdict verdict;
        try
        {
            verdict = await EvaluateAsync(message, messageType, phase, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            activity?.SetTag(AgentGuardTelemetry.Tags.Outcome, AgentGuardTelemetry.Outcomes.Error);
            activity?.SetStatus(ActivityStatusCode.Error, ex.Message);
            throw;
        }

        if (verdict.BlockingResult is { } blocking)
        {
            // a block is the policy doing its job, so the span records the outcome but not an error status
            activity?.SetTag(AgentGuardTelemetry.Tags.Outcome, AgentGuardTelemetry.Outcomes.Blocked);
            activity?.SetTag(AgentGuardTelemetry.Tags.BlockedReason, blocking.Reason);
            activity?.SetTag(AgentGuardTelemetry.Tags.Severity, blocking.Severity.ToString().ToLowerInvariant());
            throw new GuardrailViolationException(blocking, phase, _executorId);
        }

        activity?.SetTag(
            AgentGuardTelemetry.Tags.Outcome,
            verdict.WasModified ? AgentGuardTelemetry.Outcomes.Modified : AgentGuardTelemetry.Outcomes.Passed);

        return verdict.Message;
    }

    /// <summary>
    /// Guards a message of one of the inner executor's other handled types on its way in, then hands it to the
    /// inner executor, which routes it to its own handler.
    /// </summary>
    /// <param name="inner">The inner executor.</param>
    /// <param name="message">The message, wrapped in a <see cref="PortableValue"/> when it came through a catch-all route.</param>
    /// <param name="handledType">The type of the route the message came through; null for the catch-all.</param>
    /// <param name="spanName">The name of the span that records the verdict.</param>
    /// <param name="context">The workflow context.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async ValueTask ForwardAsync(
        Executor inner,
        object message,
        Type? handledType,
        string spanName,
        IWorkflowContext context,
        CancellationToken cancellationToken)
    {
        // a catch-all route receives the message wrapped; the rules look at what it carries
        var subject = message is PortableValue portable ? portable.As<object>() ?? message : message;
        var guarded = await GuardAsync(subject, handledType ?? subject.GetType(), GuardrailPhase.Input, spanName, cancellationToken)
            .ConfigureAwait(false);

        await InnerExecutor.ExecuteAsync(inner, ReferenceEquals(guarded, subject) ? message : guarded!, context, cancellationToken)
            .ConfigureAwait(false);
    }

    private ValueTask<Verdict> EvaluateAsync(
        object? message, Type messageType, GuardrailPhase phase, CancellationToken cancellationToken) =>
        message switch
        {
            // turn and reset signals only coordinate executors; they carry no text to check
            null or TurnToken or ResetChatSignal => ValueTask.FromResult(Verdict.Passed(message)),
            ChatMessage chatMessage => EvaluateTextAsync(chatMessage, chatMessage.Text, messageType, phase, cancellationToken),
            AgentResponse response => EvaluateMessagesAsync(
                response, response.Messages as IReadOnlyList<ChatMessage> ?? [.. response.Messages], messageType, phase, cancellationToken),
            IEnumerable<ChatMessage> messages => EvaluateMessagesAsync(
                messages, messages as IReadOnlyList<ChatMessage> ?? [.. messages], messageType, phase, cancellationToken),
            _ => EvaluateTextAsync(message, _textExtractor.ExtractText(message), messageType, phase, cancellationToken)
        };

    private async ValueTask<Verdict> EvaluateTextAsync(
        object message, string? text, Type messageType, GuardrailPhase phase, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(text))
            return Verdict.Passed(message);

        var result = await _chatGuard.Pipeline.RunAsync(CreateContext(text, phase, messageType, history: null), cancellationToken)
            .ConfigureAwait(false);

        if (result.IsBlocked)
            return Verdict.Blocked(result.BlockingResult!);

        return result.WasModified
            ? Verdict.Modified(Rebuild(message, messageType, result.FinalText))
            : Verdict.Passed(message);
    }

    // the guard covers the user messages on the way in and the assistant messages on the way out, as it
    // does for an agent; the newest message with text is checked whatever its role, since an executor's
    // input is often another agent's response and its output a prompt for the next one
    private async ValueTask<Verdict> EvaluateMessagesAsync(
        object message, IReadOnlyList<ChatMessage> messages, Type messageType, GuardrailPhase phase, CancellationToken cancellationToken)
    {
        var result = phase == GuardrailPhase.Input
            ? await _chatGuard.GuardInputAsync(messages, cancellationToken: cancellationToken).ConfigureAwait(false)
            : await _chatGuard.GuardOutputAsync(messages, cancellationToken: cancellationToken).ConfigureAwait(false);

        if (result.IsBlocked)
            return Verdict.Blocked(result.BlockingResult!);

        var guarded = result.Messages;
        var modified = result.WasModified;

        var newest = LastIndexWithText(guarded);
        var guardedRole = phase == GuardrailPhase.Input ? ChatRole.User : ChatRole.Assistant;

        if (newest >= 0 && guarded[newest].Role != guardedRole)
        {
            var check = await _chatGuard.Pipeline.RunAsync(
                CreateContext(guarded[newest].Text, phase, messageType, guarded), cancellationToken).ConfigureAwait(false);

            if (check.IsBlocked)
                return Verdict.Blocked(check.BlockingResult!);

            if (check.WasModified)
            {
                List<ChatMessage> rewritten = [.. guarded];
                rewritten[newest] = GuardrailChatContent.WithText(guarded[newest], check.FinalText);
                guarded = rewritten;
                modified = true;
            }
        }

        return modified
            ? Verdict.Modified(RebuildMessages(message, messageType, guarded))
            : Verdict.Passed(message);
    }

    private GuardrailContext CreateContext(
        string text, GuardrailPhase phase, Type messageType, IReadOnlyList<ChatMessage>? history) => new()
        {
            Text = text,
            Phase = phase,
            Messages = history,
            Properties = new Dictionary<string, object>
            {
                ["ExecutorId"] = _executorId,
                ["MessageType"] = messageType.Name
            }
        };

    // applies the rewritten text to the message; a message that can't be rebuilt goes on unchanged
    private object Rebuild(object message, Type messageType, string text)
    {
        switch (message)
        {
            case string:
                return text;
            case ChatMessage chatMessage:
                return GuardrailChatContent.WithText(chatMessage, text);
        }

        if (_textExtractor.TryRebuild(message, text, out var rebuilt) && messageType.IsInstanceOfType(rebuilt))
            return rebuilt;

        // the pipeline reported the rewrite as applied, so dropping it must not go unnoticed
        GuardedExecutorLog.ModificationDropped(_log, _executorId, messageType.Name);
        return message;
    }

    // puts the guarded messages back in the shape the executor declared
    private object RebuildMessages(object message, Type messageType, IReadOnlyList<ChatMessage> messages)
    {
        object? rebuilt = message switch
        {
            AgentResponse response => new AgentResponse([.. messages])
            {
                ResponseId = response.ResponseId,
                AgentId = response.AgentId,
                CreatedAt = response.CreatedAt,
                Usage = response.Usage,
                FinishReason = response.FinishReason,
#pragma warning disable MEAI001 // a background run's continuation token has to reach the next executor
                ContinuationToken = response.ContinuationToken,
#pragma warning restore MEAI001
                AdditionalProperties = response.AdditionalProperties
            },
            ChatMessage[] => messages.ToArray(),
            _ when messageType.IsAssignableFrom(typeof(List<ChatMessage>)) => new List<ChatMessage>(messages),
            _ => null
        };

        if (rebuilt is not null && messageType.IsInstanceOfType(rebuilt))
            return rebuilt;

        GuardedExecutorLog.MessagesModificationDropped(_log, _executorId, messageType.Name);
        return message;
    }

    private static int LastIndexWithText(IReadOnlyList<ChatMessage> messages)
    {
        for (var i = messages.Count - 1; i >= 0; i--)
        {
            if (!string.IsNullOrWhiteSpace(messages[i].Text))
                return i;
        }

        return -1;
    }

    private readonly record struct Verdict(object? Message, bool WasModified, GuardrailResult? BlockingResult)
    {
        public static Verdict Passed(object? message) => new(message, false, null);

        public static Verdict Modified(object message) => new(message, true, null);

        public static Verdict Blocked(GuardrailResult blockingResult) => new(null, false, blockingResult);
    }
}

/// <summary>Log messages of the guarded executors.</summary>
internal static partial class GuardedExecutorLog
{
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Guardrail modified the text for executor '{ExecutorId}', but a {MessageType} can't be rebuilt from text, so the change could NOT be applied and the original value was passed through. Implement ITextExtractor.TryRebuild for this type, or use string, ChatMessage or chat message collection messages.")]
    private static partial void LogModificationDropped(ILogger logger, string executorId, string messageType);

    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Guardrail modified the chat messages for executor '{ExecutorId}', but a {MessageType} can't be rebuilt from them, so the change could NOT be applied and the original value was passed through. Declare the messages as List<ChatMessage>, ChatMessage[] or an interface List<ChatMessage> implements.")]
    private static partial void LogMessagesModificationDropped(ILogger logger, string executorId, string messageType);

    public static void ModificationDropped(ILogger? logger, string executorId, string messageType)
    {
        if (logger is not null)
            LogModificationDropped(logger, executorId, messageType);
    }

    public static void MessagesModificationDropped(ILogger? logger, string executorId, string messageType)
    {
        if (logger is not null)
            LogMessagesModificationDropped(logger, executorId, messageType);
    }
}

/// <summary>Adapts a caller's <see cref="ILogger"/> to the <see cref="ILogger{TCategoryName}"/> the pipeline takes.</summary>
internal sealed class LoggerWrapper(ILogger inner) : ILogger<GuardrailPipeline>
{
    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => inner.BeginScope(state);

    public bool IsEnabled(LogLevel logLevel) => inner.IsEnabled(logLevel);

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        => inner.Log(logLevel, eventId, state, exception, formatter);
}
