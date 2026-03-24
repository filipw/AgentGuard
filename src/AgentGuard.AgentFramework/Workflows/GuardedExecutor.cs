using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Guardrails;
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
        _pipeline = new GuardrailPipeline(policy, logger);
    }

    public override async ValueTask HandleAsync(TInput message, IWorkflowContext context, CancellationToken cancellationToken = default)
    {
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
                throw new GuardrailViolationException(result.BlockingResult!, GuardrailPhase.Input, _inner.Id);

            if (result.WasModified)
                message = ReconstructInput(message, result.FinalText);
        }

        await _inner.HandleAsync(message, context, cancellationToken);
    }

    private static TInput ReconstructInput(TInput original, string modifiedText)
    {
        if (original is string)
            return (TInput)(object)modifiedText;

        if (original is ChatMessage chatMessage)
            return (TInput)(object)new ChatMessage(chatMessage.Role, modifiedText);

        // Cannot reconstruct arbitrary types - pass original through
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
        _pipeline = new GuardrailPipeline(policy, logger);
    }

    public override async ValueTask<TOutput> HandleAsync(TInput message, IWorkflowContext context, CancellationToken cancellationToken = default)
    {
        // --- Input guardrails ---
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
                throw new GuardrailViolationException(inputResult.BlockingResult!, GuardrailPhase.Input, _inner.Id);

            if (inputResult.WasModified)
                message = ReconstructInput(message, inputResult.FinalText);
        }

        // --- Execute inner ---
        var output = await _inner.HandleAsync(message, context, cancellationToken);

        // --- Output guardrails ---
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
                throw new GuardrailViolationException(outputResult.BlockingResult!, GuardrailPhase.Output, _inner.Id);

            if (outputResult.WasModified)
                output = ReconstructOutput(output, outputResult.FinalText);
        }

        return output;
    }

    private static TInput ReconstructInput(TInput original, string modifiedText)
    {
        if (original is string)
            return (TInput)(object)modifiedText;

        if (original is ChatMessage chatMessage)
            return (TInput)(object)new ChatMessage(chatMessage.Role, modifiedText);

        return original;
    }

    private static TOutput ReconstructOutput(TOutput original, string modifiedText)
    {
        if (original is string)
            return (TOutput)(object)modifiedText;

        if (original is ChatMessage chatMessage)
            return (TOutput)(object)new ChatMessage(chatMessage.Role, modifiedText);

        return original;
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
