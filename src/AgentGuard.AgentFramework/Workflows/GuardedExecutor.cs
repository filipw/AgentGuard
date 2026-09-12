using System.Diagnostics;
using AgentGuard.Core.Abstractions;
using Microsoft.Extensions.Logging;
using AgentGuard.Core.Guardrails;
using AgentGuard.Core.Telemetry;
using Microsoft.Agents.AI.Workflows;
using Microsoft.Extensions.AI;

namespace AgentGuard.AgentFramework.Workflows;

/// <summary>
/// Wraps a void-return executor with input guardrails.
/// If a guardrail blocks, a <see cref="GuardrailViolationException"/> is thrown.
/// If a guardrail modifies text and TInput is string or ChatMessage, the modified value is passed to the inner executor.
/// </summary>
public sealed class GuardedExecutor<TInput> : Executor<TInput>
{
    private readonly Executor<TInput> _inner;
    private readonly GuardrailPipeline _pipeline;
    private readonly ITextExtractor _textExtractor;
    private readonly ILogger? _log;

    internal GuardedExecutor(
        Executor<TInput> inner,
        IGuardrailPolicy policy,
        GuardedExecutorOptions? options = null)
        : base($"guarded-{inner.Id}")
    {
        _inner = inner;
        _textExtractor = options?.TextExtractor ?? DefaultTextExtractor.Instance;

        Microsoft.Extensions.Logging.ILogger<GuardrailPipeline> logger = options?.Logger is not null
            ? new LoggerWrapper(options.Logger)
            : Microsoft.Extensions.Logging.Abstractions.NullLogger<GuardrailPipeline>.Instance;
        _pipeline = new GuardrailPipeline(policy, logger, options?.Ledger);
        _log = options?.Logger;
    }

    /// <inheritdoc />
    public override async ValueTask HandleAsync(TInput message, IWorkflowContext context, CancellationToken cancellationToken = default)
    {
        using var guardActivity = AgentGuardTelemetry.ActivitySource.StartActivity(
            AgentGuardTelemetry.Spans.ExecutorGuard);

        guardActivity?.SetTag(AgentGuardTelemetry.Tags.ExecutorId, _inner.Id);
        guardActivity?.SetTag(AgentGuardTelemetry.Tags.Phase, "input");
        guardActivity?.SetTag(AgentGuardTelemetry.Tags.MessageType, typeof(TInput).Name);

        var text = _textExtractor.ExtractText(message);

        if (!string.IsNullOrEmpty(text))
        {
            var guardrailContext = new GuardrailContext
            {
                Text = text,
                Phase = GuardrailPhase.Input,
                Properties = new Dictionary<string, object>
                {
                    ["ExecutorId"] = _inner.Id,
                    ["MessageType"] = typeof(TInput).Name
                }
            };

            var result = await _pipeline.RunAsync(guardrailContext, cancellationToken);

            if (result.IsBlocked)
            {
                guardActivity?.SetTag(AgentGuardTelemetry.Tags.Outcome, AgentGuardTelemetry.Outcomes.Blocked);
                guardActivity?.SetStatus(ActivityStatusCode.Error, result.BlockingResult?.Reason);
                throw new GuardrailViolationException(result.BlockingResult!, GuardrailPhase.Input, _inner.Id);
            }

            if (result.WasModified)
            {
                guardActivity?.SetTag(AgentGuardTelemetry.Tags.Outcome, AgentGuardTelemetry.Outcomes.Modified);
                message = ReconstructInput(message, result.FinalText, _log, _inner.Id);
            }
            else
            {
                guardActivity?.SetTag(AgentGuardTelemetry.Tags.Outcome, AgentGuardTelemetry.Outcomes.Passed);
            }
        }
        else
        {
            guardActivity?.SetTag(AgentGuardTelemetry.Tags.Outcome, AgentGuardTelemetry.Outcomes.Passed);
        }

        await _inner.HandleAsync(message, context, cancellationToken);
    }

    private static TInput ReconstructInput(TInput original, string modifiedText, ILogger? log, string executorId)
    {
        if (original is string)
            return (TInput)(object)modifiedText;

        if (original is ChatMessage chatMessage)
            return (TInput)(object)new ChatMessage(chatMessage.Role, modifiedText);

        // An arbitrary type cannot be rebuilt from text, so the original goes through unchanged -
        // while the pipeline has already reported Modified. Silently dropping a redaction that was
        // reported as applied is the dangerous half, so say so loudly.
        GuardedExecutorLog.ModificationDropped(log, executorId, typeof(TInput).Name);
        return original;
    }
}

/// <summary>
/// Wraps a typed-return executor with input and output guardrails.
/// If a guardrail blocks on either side, a <see cref="GuardrailViolationException"/> is thrown.
/// </summary>
public sealed class GuardedExecutor<TInput, TOutput> : Executor<TInput, TOutput>
{
    private readonly Executor<TInput, TOutput> _inner;
    private readonly GuardrailPipeline _pipeline;
    private readonly ITextExtractor _textExtractor;
    private readonly ILogger? _log;

    internal GuardedExecutor(
        Executor<TInput, TOutput> inner,
        IGuardrailPolicy policy,
        GuardedExecutorOptions? options = null)
        : base($"guarded-{inner.Id}")
    {
        _inner = inner;
        _textExtractor = options?.TextExtractor ?? DefaultTextExtractor.Instance;

        Microsoft.Extensions.Logging.ILogger<GuardrailPipeline> logger = options?.Logger is not null
            ? new LoggerWrapper(options.Logger)
            : Microsoft.Extensions.Logging.Abstractions.NullLogger<GuardrailPipeline>.Instance;
        _pipeline = new GuardrailPipeline(policy, logger, options?.Ledger);
        _log = options?.Logger;
    }

    /// <inheritdoc />
    public override async ValueTask<TOutput> HandleAsync(TInput message, IWorkflowContext context, CancellationToken cancellationToken = default)
    {
        // --- input guardrails ---
        using var inputGuardActivity = AgentGuardTelemetry.ActivitySource.StartActivity(
            $"{AgentGuardTelemetry.Spans.ExecutorGuard} input");

        inputGuardActivity?.SetTag(AgentGuardTelemetry.Tags.ExecutorId, _inner.Id);
        inputGuardActivity?.SetTag(AgentGuardTelemetry.Tags.Phase, "input");
        inputGuardActivity?.SetTag(AgentGuardTelemetry.Tags.MessageType, typeof(TInput).Name);

        var inputText = _textExtractor.ExtractText(message);

        if (!string.IsNullOrEmpty(inputText))
        {
            var inputContext = new GuardrailContext
            {
                Text = inputText,
                Phase = GuardrailPhase.Input,
                Properties = new Dictionary<string, object>
                {
                    ["ExecutorId"] = _inner.Id,
                    ["MessageType"] = typeof(TInput).Name
                }
            };

            var inputResult = await _pipeline.RunAsync(inputContext, cancellationToken);

            if (inputResult.IsBlocked)
            {
                inputGuardActivity?.SetTag(AgentGuardTelemetry.Tags.Outcome, AgentGuardTelemetry.Outcomes.Blocked);
                inputGuardActivity?.SetStatus(ActivityStatusCode.Error, inputResult.BlockingResult?.Reason);
                throw new GuardrailViolationException(inputResult.BlockingResult!, GuardrailPhase.Input, _inner.Id);
            }

            if (inputResult.WasModified)
            {
                inputGuardActivity?.SetTag(AgentGuardTelemetry.Tags.Outcome, AgentGuardTelemetry.Outcomes.Modified);
                message = ReconstructInput(message, inputResult.FinalText, _log, _inner.Id);
            }
            else
            {
                inputGuardActivity?.SetTag(AgentGuardTelemetry.Tags.Outcome, AgentGuardTelemetry.Outcomes.Passed);
            }
        }
        else
        {
            inputGuardActivity?.SetTag(AgentGuardTelemetry.Tags.Outcome, AgentGuardTelemetry.Outcomes.Passed);
        }

        inputGuardActivity?.Dispose();

        // --- execute inner ---
        var output = await _inner.HandleAsync(message, context, cancellationToken);

        // --- output guardrails ---
        using var outputGuardActivity = AgentGuardTelemetry.ActivitySource.StartActivity(
            $"{AgentGuardTelemetry.Spans.ExecutorGuard} output");

        outputGuardActivity?.SetTag(AgentGuardTelemetry.Tags.ExecutorId, _inner.Id);
        outputGuardActivity?.SetTag(AgentGuardTelemetry.Tags.Phase, "output");
        outputGuardActivity?.SetTag(AgentGuardTelemetry.Tags.MessageType, typeof(TOutput).Name);

        var outputText = _textExtractor.ExtractText(output);

        if (!string.IsNullOrEmpty(outputText))
        {
            var outputContext = new GuardrailContext
            {
                Text = outputText,
                Phase = GuardrailPhase.Output,
                Properties = new Dictionary<string, object>
                {
                    ["ExecutorId"] = _inner.Id,
                    ["MessageType"] = typeof(TOutput).Name
                }
            };

            var outputResult = await _pipeline.RunAsync(outputContext, cancellationToken);

            if (outputResult.IsBlocked)
            {
                outputGuardActivity?.SetTag(AgentGuardTelemetry.Tags.Outcome, AgentGuardTelemetry.Outcomes.Blocked);
                outputGuardActivity?.SetStatus(ActivityStatusCode.Error, outputResult.BlockingResult?.Reason);
                throw new GuardrailViolationException(outputResult.BlockingResult!, GuardrailPhase.Output, _inner.Id);
            }

            if (outputResult.WasModified)
            {
                outputGuardActivity?.SetTag(AgentGuardTelemetry.Tags.Outcome, AgentGuardTelemetry.Outcomes.Modified);
                output = ReconstructOutput(output, outputResult.FinalText, _log, _inner.Id);
            }
            else
            {
                outputGuardActivity?.SetTag(AgentGuardTelemetry.Tags.Outcome, AgentGuardTelemetry.Outcomes.Passed);
            }
        }
        else
        {
            outputGuardActivity?.SetTag(AgentGuardTelemetry.Tags.Outcome, AgentGuardTelemetry.Outcomes.Passed);
        }

        return output;
    }

    private static TInput ReconstructInput(TInput original, string modifiedText, ILogger? log, string executorId)
    {
        if (original is string)
            return (TInput)(object)modifiedText;

        if (original is ChatMessage chatMessage)
            return (TInput)(object)new ChatMessage(chatMessage.Role, modifiedText);

        GuardedExecutorLog.ModificationDropped(log, executorId, typeof(TInput).Name);
        return original;
    }

    private static TOutput ReconstructOutput(TOutput original, string modifiedText, ILogger? log, string executorId)
    {
        if (original is string)
            return (TOutput)(object)modifiedText;

        if (original is ChatMessage chatMessage)
            return (TOutput)(object)new ChatMessage(chatMessage.Role, modifiedText);

        GuardedExecutorLog.ModificationDropped(log, executorId, typeof(TOutput).Name);
        return original;
    }
}

/// <summary>Log messages shared by both <c>GuardedExecutor</c> variants.</summary>
internal static partial class GuardedExecutorLog
{
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Guardrail modified the text for executor '{ExecutorId}', but {MessageType} is neither string nor ChatMessage, so the change could NOT be applied and the original value was passed through. Supply an ITextExtractor that can rebuild this type, or use string/ChatMessage.")]
    private static partial void LogModificationDropped(ILogger logger, string executorId, string messageType);

    public static void ModificationDropped(ILogger? logger, string executorId, string messageType)
    {
        if (logger is not null)
            LogModificationDropped(logger, executorId, messageType);
    }
}

/// <summary>
/// Adapter that wraps a generic ILogger as ILogger&lt;GuardrailPipeline&gt;.
/// </summary>
internal sealed class LoggerWrapper : Microsoft.Extensions.Logging.ILogger<GuardrailPipeline>
{
    private readonly Microsoft.Extensions.Logging.ILogger _inner;
    internal LoggerWrapper(Microsoft.Extensions.Logging.ILogger inner) => _inner = inner;

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => _inner.BeginScope(state);
    public bool IsEnabled(Microsoft.Extensions.Logging.LogLevel logLevel) => _inner.IsEnabled(logLevel);
    public void Log<TState>(Microsoft.Extensions.Logging.LogLevel logLevel, Microsoft.Extensions.Logging.EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        => _inner.Log(logLevel, eventId, state, exception, formatter);
}
