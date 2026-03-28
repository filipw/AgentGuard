namespace AgentGuard.Core.Abstractions;

[Flags]
public enum GuardrailPhase
{
    Input = 1,
    Output = 2,
    Both = Input | Output
}

public sealed record GuardrailResult
{
    public bool IsBlocked { get; init; }
    public bool IsModified { get; init; }
    public string? Reason { get; init; }
    public string? ModifiedText { get; init; }
    public string RuleName { get; init; } = "";
    public GuardrailSeverity Severity { get; init; } = GuardrailSeverity.None;
    public IReadOnlyDictionary<string, object>? Metadata { get; init; }

    /// <summary>
    /// True when the rule encountered an error (e.g. API timeout, model unavailable)
    /// and returned a default result rather than an actual classification.
    /// Check this to distinguish "checked and clean" from "failed to check".
    /// </summary>
    public bool IsError { get; init; }

    public static GuardrailResult Passed() => new() { IsBlocked = false };

    public static GuardrailResult Blocked(string reason, GuardrailSeverity severity = GuardrailSeverity.High) =>
        new() { IsBlocked = true, Reason = reason, Severity = severity };

    public static GuardrailResult Modified(string modifiedText, string reason) =>
        new() { IsModified = true, ModifiedText = modifiedText, Reason = reason };

    /// <summary>
    /// Creates an error result based on the configured <see cref="ErrorBehavior"/>.
    /// Always sets <see cref="IsError"/> = true and includes error metadata.
    /// </summary>
    public static GuardrailResult Error(string ruleName, ErrorBehavior behavior, string? detail = null)
    {
        var metadata = new Dictionary<string, object> { ["error"] = true };
        if (detail is not null)
            metadata["errorDetail"] = detail;

        return behavior switch
        {
            ErrorBehavior.FailClosed => new GuardrailResult
            {
                IsBlocked = true,
                IsError = true,
                Reason = $"{ruleName} encountered an error and ErrorBehavior is FailClosed",
                Severity = GuardrailSeverity.High,
                Metadata = metadata
            },
            ErrorBehavior.Warn => new GuardrailResult
            {
                IsBlocked = false,
                IsError = true,
                Metadata = metadata
            },
            _ => new GuardrailResult
            {
                IsBlocked = false,
                IsError = true,
                Metadata = metadata
            }
        };
    }
}

/// <summary>
/// Configures what happens when a guardrail rule encounters an error
/// (e.g. API timeout, model unavailable, HTTP failure).
/// </summary>
public enum ErrorBehavior
{
    /// <summary>Pass the text through (fail-open). Default for most rules.</summary>
    FailOpen = 0,
    /// <summary>Pass the text through but attach error metadata for downstream inspection.</summary>
    Warn = 1,
    /// <summary>Block the text (fail-closed). Use when safety is more important than availability.</summary>
    FailClosed = 2
}

public enum GuardrailSeverity
{
    None = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
}

public sealed record GuardrailContext
{
    public required string Text { get; init; }
    public required GuardrailPhase Phase { get; init; }
    public IReadOnlyList<Microsoft.Extensions.AI.ChatMessage>? Messages { get; init; }
    public string? AgentName { get; init; }
    public IDictionary<string, object> Properties { get; init; } = new Dictionary<string, object>();
}

public interface IGuardrailRule
{
    string Name { get; }
    GuardrailPhase Phase { get; }
    int Order => 100;

    ValueTask<GuardrailResult> EvaluateAsync(
        GuardrailContext context,
        CancellationToken cancellationToken = default);
}
