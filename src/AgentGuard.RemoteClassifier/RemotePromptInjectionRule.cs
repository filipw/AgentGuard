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
/// Input is blocked when an injection label's score reaches the threshold: the predicted label's
/// score, or, when the classifier reports every label's score, the injection label's own score even
/// if another label scored higher. A failed call, a timeout, or a result without a usable label and
/// score is an error handled by <see cref="RemotePromptInjectionOptions.OnError"/>; by default the
/// rule fails open, so the rule passes and downstream rules (LLM, etc.) continue to evaluate.
/// </summary>
public sealed partial class RemotePromptInjectionRule : IGuardrailRule
{
    // the longest delay CancellationTokenSource.CancelAfter accepts
    private const double MaxTimeoutMilliseconds = uint.MaxValue - 1d;

    private readonly IRemoteClassifier _classifier;
    private readonly RemotePromptInjectionOptions _options;
    private readonly HashSet<string> _injectionLabels;
    private readonly ILogger _logger;

    /// <summary>
    /// Creates a new remote prompt injection rule.
    /// </summary>
    /// <param name="classifier">The remote classifier to call.</param>
    /// <param name="options">Configuration options.</param>
    /// <param name="logger">Optional logger.</param>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when <see cref="RemotePromptInjectionOptions.Threshold"/> is NaN or outside 0.0-1.0, or
    /// <see cref="RemotePromptInjectionOptions.Timeout"/> is not a positive time span (or
    /// <see cref="Timeout.InfiniteTimeSpan"/>).
    /// </exception>
    /// <exception cref="ArgumentException">Thrown when <see cref="RemotePromptInjectionOptions.InjectionLabels"/> is empty.</exception>
    public RemotePromptInjectionRule(
        IRemoteClassifier classifier,
        RemotePromptInjectionOptions? options = null,
        ILogger<RemotePromptInjectionRule>? logger = null)
    {
        _classifier = classifier ?? throw new ArgumentNullException(nameof(classifier));
        _options = options ?? new();
        Validate(_options);

        // labels match ignoring case and independently of the current culture, whatever comparer the
        // configured set uses
        _injectionLabels = new HashSet<string>(_options.InjectionLabels, StringComparer.OrdinalIgnoreCase);
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

        ClassificationResult result;
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(_options.Timeout);

            result = await _classifier.ClassifyAsync(context.Text, cts.Token);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            LogTimeout(_logger, _options.Timeout.TotalMilliseconds);
            return HandleFailure($"Timed out after {_options.Timeout.TotalMilliseconds}ms");
        }
        catch (Exception ex) when (cancellationToken.IsCancellationRequested && ex is not OperationCanceledException)
        {
            // the caller gave up and the call failed as it was torn down: that is a cancellation, not a
            // classifier failure for OnError to turn into a pass or a block
            throw new OperationCanceledException("The remote classification was canceled.", ex, cancellationToken);
        }
        catch (HttpRequestException ex)
        {
            LogHttpError(_logger, ex);
            return HandleFailure(ex.Message);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            LogUnexpectedError(_logger, ex);
            return HandleFailure(ex.Message);
        }

        if (DescribeUnusableResult(result) is { } problem)
        {
            LogUnusableResult(_logger, problem);
            return HandleFailure(problem);
        }

        if (FindInjectionLabel(result) is not { } injection || injection.Score < _options.Threshold)
            return GuardrailResult.Passed();

        var metadata = new Dictionary<string, object>
        {
            ["label"] = injection.Label,
            ["threshold"] = _options.Threshold
        };

        if (_options.IncludeConfidence)
        {
            metadata["confidence"] = injection.Score;
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
            Reason = $"Remote classifier detected prompt injection (label: {injection.Label}, confidence: {injection.Score:F3})",
            Severity = GuardrailSeverity.High,
            Metadata = metadata
        };
    }

    private GuardrailResult HandleFailure(string? detail = null) =>
        GuardrailResult.Error(Name, _options.OnError, detail);

    // the highest-scoring injection label: the predicted label, or another label the classifier scored
    private LabelScore? FindInjectionLabel(ClassificationResult result)
    {
        LabelScore? injection = _injectionLabels.Contains(result.Label) ? new LabelScore(result.Label, result.Score) : null;
        foreach (var entry in result.Scores ?? [])
        {
            if (_injectionLabels.Contains(entry.Label) && (injection is null || entry.Score > injection.Value.Score))
                injection = entry;
        }

        return injection;
    }

    // a result the rule cannot judge; treating it as clean would silently let everything through
    private static string? DescribeUnusableResult(ClassificationResult? result)
    {
        if (result is null)
            return "The remote classifier returned no result.";

        if (string.IsNullOrWhiteSpace(result.Label) || !float.IsFinite(result.Score))
            return "The remote classifier returned no usable label and score.";

        foreach (var entry in result.Scores ?? [])
        {
            if (string.IsNullOrWhiteSpace(entry.Label) || !float.IsFinite(entry.Score))
                return "One of the label scores the remote classifier returned has no usable label or score.";
        }

        return null;
    }

    private static void Validate(RemotePromptInjectionOptions options)
    {
        if (options.Threshold is not (>= 0f and <= 1f))
            throw new ArgumentOutOfRangeException(nameof(options), options.Threshold, "Threshold must be between 0.0 and 1.0.");

        if (options.Timeout != Timeout.InfiniteTimeSpan
            && (options.Timeout <= TimeSpan.Zero || options.Timeout.TotalMilliseconds > MaxTimeoutMilliseconds))
        {
            throw new ArgumentOutOfRangeException(
                nameof(options), options.Timeout, "Timeout must be a positive time span of at most about 49 days, or Timeout.InfiniteTimeSpan for none.");
        }

        if (options.InjectionLabels is not { Count: > 0 })
            throw new ArgumentException("InjectionLabels must contain at least one label.", nameof(options));
    }

    [LoggerMessage(Level = LogLevel.Warning, Message = "Remote classifier timed out after {TimeoutMs}ms")]
    private static partial void LogTimeout(ILogger logger, double timeoutMs);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Remote classifier HTTP request failed")]
    private static partial void LogHttpError(ILogger logger, Exception ex);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Remote classifier encountered an unexpected error")]
    private static partial void LogUnexpectedError(ILogger logger, Exception ex);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Remote classifier result is unusable: {Problem}")]
    private static partial void LogUnusableResult(ILogger logger, string problem);
}
