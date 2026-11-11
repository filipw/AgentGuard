using System.Globalization;
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
/// if another label scored higher. Labels are compared by their letters and digits, ignoring case, so
/// <c>prompt_injection</c>, <c>prompt-injection</c> and <c>PromptInjection</c> are one label. Text
/// longer than <see cref="RemotePromptInjectionOptions.MaxCharactersPerRequest"/> is classified in
/// overlapping windows, one request each, and an injection in any window blocks.
///
/// A failed call, a timeout, a result without a usable label and score, a predicted label that is
/// neither an injection nor a safe label, or text that needs more requests than
/// <see cref="RemotePromptInjectionOptions.MaxRequests"/> is an error handled by
/// <see cref="RemotePromptInjectionOptions.OnError"/>; by default the rule fails open, so the rule
/// passes and downstream rules (LLM, etc.) continue to evaluate.
/// </summary>
public sealed partial class RemotePromptInjectionRule : IGuardrailRule
{
    // the longest delay CancellationTokenSource.CancelAfter accepts
    private const double MaxTimeoutMilliseconds = uint.MaxValue - 1d;

    private readonly IRemoteClassifier _classifier;
    private readonly RemotePromptInjectionOptions _options;
    private readonly HashSet<string> _injectionLabels;
    private readonly HashSet<string> _safeLabels;
    private readonly int _windowOverlap;
    private readonly ILogger _logger;

    /// <summary>
    /// Creates a new remote prompt injection rule.
    /// </summary>
    /// <param name="classifier">The remote classifier to call.</param>
    /// <param name="options">Configuration options.</param>
    /// <param name="logger">Optional logger.</param>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when <see cref="RemotePromptInjectionOptions.Threshold"/> is NaN or outside 0.0-1.0,
    /// <see cref="RemotePromptInjectionOptions.Timeout"/> is not a positive time span (or
    /// <see cref="Timeout.InfiniteTimeSpan"/>), <see cref="RemotePromptInjectionOptions.MaxCharactersPerRequest"/>
    /// is below 1, <see cref="RemotePromptInjectionOptions.WindowOverlapCharacters"/> is negative or over
    /// half of it, or <see cref="RemotePromptInjectionOptions.MaxRequests"/> is negative.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// Thrown when <see cref="RemotePromptInjectionOptions.InjectionLabels"/> or
    /// <see cref="RemotePromptInjectionOptions.SafeLabels"/> is empty, holds a label without a letter
    /// or digit, or the two share a label.
    /// </exception>
    public RemotePromptInjectionRule(
        IRemoteClassifier classifier,
        RemotePromptInjectionOptions? options = null,
        ILogger<RemotePromptInjectionRule>? logger = null)
    {
        _classifier = classifier ?? throw new ArgumentNullException(nameof(classifier));
        _options = options ?? new();
        Validate(_options);

        _injectionLabels = NormalizeLabels(_options.InjectionLabels, nameof(RemotePromptInjectionOptions.InjectionLabels), nameof(options));
        _safeLabels = NormalizeLabels(_options.SafeLabels, nameof(RemotePromptInjectionOptions.SafeLabels), nameof(options));

        // a label in both sets would be an injection or clean depending on which set is asked first
        if (_options.SafeLabels.FirstOrDefault(label => _injectionLabels.Contains(NormalizeLabel(label))) is { } shared)
        {
            throw new ArgumentException(
                $"'{shared}' is in both InjectionLabels and SafeLabels; a label can only mean one of them.", nameof(options));
        }

        _windowOverlap = _options.WindowOverlapCharacters ?? _options.MaxCharactersPerRequest / 5;
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

        var windows = TextWindows.Split(context.Text, _options.MaxCharactersPerRequest, _windowOverlap);
        var requestCount = _options.MaxRequests > 0 ? Math.Min(windows.Count, _options.MaxRequests) : windows.Count;

        string? tooLong = null;
        if (requestCount < windows.Count)
        {
            tooLong = string.Create(CultureInfo.InvariantCulture,
                $"The text needs {windows.Count} requests of up to {_options.MaxCharactersPerRequest} characters, over the MaxRequests limit of {_options.MaxRequests}.");
            LogTooManyRequests(_logger, windows.Count, _options.MaxRequests);

            // the text is blocked whatever the windows within the limit say, so they are not sent
            if (_options.OnError == ErrorBehavior.FailClosed)
                return HandleFailure(tooLong);
        }

        for (var index = 0; index < requestCount; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var outcome = await ClassifyAsync(windows[index], cancellationToken);

            // stop rather than keep calling a failing classifier once per remaining window
            if (outcome.Failure is not null)
                return HandleFailure(outcome.Failure);

            if (outcome.Injection is { } injection)
                return Blocked(injection, outcome.Result!, index, windows.Count);
        }

        // the windows that were classified are clean, but the rest of the text was never looked at
        return tooLong is null ? GuardrailResult.Passed() : HandleFailure(tooLong);
    }

    // one request: a failure, an injection at or above the threshold, or neither (clean)
    private async ValueTask<WindowOutcome> ClassifyAsync(string text, CancellationToken cancellationToken)
    {
        ClassificationResult result;
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(_options.Timeout);

            result = await _classifier.ClassifyAsync(text, cts.Token);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            LogTimeout(_logger, _options.Timeout.TotalMilliseconds);
            return WindowOutcome.Failed($"Timed out after {_options.Timeout.TotalMilliseconds}ms");
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
            return WindowOutcome.Failed(ex.Message);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            LogUnexpectedError(_logger, ex);
            return WindowOutcome.Failed(ex.Message);
        }

        if (DescribeUnusableResult(result) is { } problem)
        {
            LogUnusableResult(_logger, problem);
            return WindowOutcome.Failed(problem);
        }

        if (FindInjectionLabel(result) is { } injection && injection.Score >= _options.Threshold)
            return new WindowOutcome(result, injection, Failure: null);

        // a label the rule was never told about says nothing either way; reading it as clean would
        // let everything through whenever the model's labels and the configured ones disagree
        if (!IsKnownLabel(result.Label))
        {
            var unknown = $"The remote classifier predicted the label '{result.Label}', which is in neither InjectionLabels nor SafeLabels.";
            LogUnusableResult(_logger, unknown);
            return WindowOutcome.Failed(unknown);
        }

        return new WindowOutcome(result, Injection: null, Failure: null);
    }

    private GuardrailResult Blocked(LabelScore injection, ClassificationResult result, int windowIndex, int windowCount)
    {
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

        if (windowCount > 1)
        {
            metadata["window"] = windowIndex;
            metadata["windowCount"] = windowCount;
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
        LabelScore? injection = IsInjectionLabel(result.Label) ? new LabelScore(result.Label, result.Score) : null;
        foreach (var entry in result.Scores ?? [])
        {
            if (IsInjectionLabel(entry.Label) && (injection is null || entry.Score > injection.Value.Score))
                injection = entry;
        }

        return injection;
    }

    private bool IsInjectionLabel(string label) => _injectionLabels.Contains(NormalizeLabel(label));

    private bool IsKnownLabel(string label)
    {
        var normalized = NormalizeLabel(label);
        return _injectionLabels.Contains(normalized) || _safeLabels.Contains(normalized);
    }

    /// <summary>
    /// The form labels are compared in: letters and digits only, upper-cased independently of the
    /// culture, so the separators and casing a model card happens to use don't matter.
    /// </summary>
    internal static string NormalizeLabel(string label)
    {
        Span<char> buffer = label.Length <= 128 ? stackalloc char[label.Length] : new char[label.Length];
        var length = 0;
        foreach (var c in label)
        {
            if (char.IsLetterOrDigit(c))
                buffer[length++] = char.ToUpperInvariant(c);
        }

        return new string(buffer[..length]);
    }

    private static HashSet<string> NormalizeLabels(ISet<string> labels, string setName, string paramName)
    {
        var normalized = new HashSet<string>(StringComparer.Ordinal);
        foreach (var label in labels)
        {
            var form = label is null ? "" : NormalizeLabel(label);
            if (form.Length == 0)
                throw new ArgumentException($"{setName} holds a label without a letter or digit: '{label}'.", paramName);

            normalized.Add(form);
        }

        return normalized;
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

        // without one, no classification could ever come back clean
        if (options.SafeLabels is not { Count: > 0 })
            throw new ArgumentException("SafeLabels must contain at least one label.", nameof(options));

        if (options.MaxCharactersPerRequest < 1)
        {
            throw new ArgumentOutOfRangeException(
                nameof(options), options.MaxCharactersPerRequest, "MaxCharactersPerRequest must be at least 1.");
        }

        // windows that overlap by more than half would barely advance through the text
        if (options.WindowOverlapCharacters is { } overlap && (overlap < 0 || overlap > options.MaxCharactersPerRequest / 2))
        {
            throw new ArgumentOutOfRangeException(
                nameof(options), overlap, "WindowOverlapCharacters must be between 0 and half of MaxCharactersPerRequest.");
        }

        if (options.MaxRequests < 0)
            throw new ArgumentOutOfRangeException(nameof(options), options.MaxRequests, "MaxRequests must be 0 (no limit) or greater.");
    }

    private readonly record struct WindowOutcome(ClassificationResult? Result, LabelScore? Injection, string? Failure)
    {
        public static WindowOutcome Failed(string detail) => new(Result: null, Injection: null, Failure: detail);
    }

    [LoggerMessage(Level = LogLevel.Warning, Message = "Remote classifier timed out after {TimeoutMs}ms")]
    private static partial void LogTimeout(ILogger logger, double timeoutMs);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Remote classifier HTTP request failed")]
    private static partial void LogHttpError(ILogger logger, Exception ex);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Remote classifier encountered an unexpected error")]
    private static partial void LogUnexpectedError(ILogger logger, Exception ex);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Remote classifier result is unusable: {Problem}")]
    private static partial void LogUnusableResult(ILogger logger, string problem);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Remote classifier input needs {RequestCount} requests, over the limit of {MaxRequests}")]
    private static partial void LogTooManyRequests(ILogger logger, int requestCount, int maxRequests);
}
