using AgentGuard.Core.Abstractions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace AgentGuard.RemoteClassifier;

/// <summary>
/// Prompt injection detection rule that calls a remote ML classifier via HTTP.
/// Designed for high-accuracy models like Sentinel-v2 running on local model servers
/// (Ollama, vLLM, HuggingFace TGI) or custom endpoints (FastAPI, etc.).
///
/// Order 13 - between ONNX (12) and LLM (15). Provides ML-grade accuracy without
/// requiring ONNX Runtime native binaries - just an HTTP endpoint.
///
/// Fails open by default: if the remote classifier is unreachable, the rule passes
/// and downstream rules (LLM, etc.) continue to evaluate.
/// </summary>
public sealed partial class RemotePromptInjectionRule : IGuardrailRule
{
    private readonly IRemoteClassifier _classifier;
    private readonly RemotePromptInjectionOptions _options;
    private readonly ILogger _logger;

    /// <summary>
    /// Creates a new remote prompt injection rule.
    /// </summary>
    /// <param name="classifier">The remote classifier to call.</param>
    /// <param name="options">Configuration options.</param>
    /// <param name="logger">Optional logger.</param>
    public RemotePromptInjectionRule(
        IRemoteClassifier classifier,
        RemotePromptInjectionOptions? options = null,
        ILogger<RemotePromptInjectionRule>? logger = null)
    {
        _classifier = classifier ?? throw new ArgumentNullException(nameof(classifier));
        _options = options ?? new();
        _logger = logger ?? NullLogger<RemotePromptInjectionRule>.Instance;
    }

    /// <inheritdoc />
    public string Name => "remote-prompt-injection";

    /// <inheritdoc />
    public GuardrailPhase Phase => GuardrailPhase.Input;

    /// <inheritdoc />
    public int Order => 13;

    /// <inheritdoc />
    public async ValueTask<GuardrailResult> EvaluateAsync(
        GuardrailContext context,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(context.Text))
            return GuardrailResult.Passed();

        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(_options.Timeout);

            var result = await _classifier.ClassifyAsync(context.Text, cts.Token);

            var isInjection = _options.InjectionLabels.Contains(result.Label) &&
                              result.Score >= _options.Threshold;

            if (isInjection)
            {
                var metadata = new Dictionary<string, object>
                {
                    ["label"] = result.Label,
                    ["threshold"] = _options.Threshold
                };

                if (_options.IncludeConfidence)
                {
                    metadata["confidence"] = result.Score;
                }

                if (result.Model is not null)
                {
                    metadata["model"] = result.Model;
                }

                if (result.Metadata is not null)
                {
                    foreach (var (key, value) in result.Metadata)
                    {
                        metadata.TryAdd(key, value);
                    }
                }

                return new GuardrailResult
                {
                    IsBlocked = true,
                    Reason = $"Remote classifier detected prompt injection (label: {result.Label}, confidence: {result.Score:F3})",
                    Severity = GuardrailSeverity.High,
                    Metadata = metadata
                };
            }

            return GuardrailResult.Passed();
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            LogTimeout(_logger, _options.Timeout.TotalMilliseconds);
            return HandleFailure();
        }
        catch (HttpRequestException ex)
        {
            LogHttpError(_logger, ex);
            return HandleFailure();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            LogUnexpectedError(_logger, ex);
            return HandleFailure();
        }
    }

    private GuardrailResult HandleFailure()
    {
        if (_options.FailOpen)
        {
            return GuardrailResult.Passed();
        }

        return new GuardrailResult
        {
            IsBlocked = true,
            Reason = "Remote classifier is unavailable and FailOpen is disabled",
            Severity = GuardrailSeverity.Medium
        };
    }

    [LoggerMessage(Level = LogLevel.Warning, Message = "Remote classifier timed out after {TimeoutMs}ms")]
    private static partial void LogTimeout(ILogger logger, double timeoutMs);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Remote classifier HTTP request failed")]
    private static partial void LogHttpError(ILogger logger, Exception ex);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Remote classifier encountered an unexpected error")]
    private static partial void LogUnexpectedError(ILogger logger, Exception ex);
}
