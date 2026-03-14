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

    public static GuardrailResult Passed() => new() { IsBlocked = false };

    public static GuardrailResult Blocked(string reason, GuardrailSeverity severity = GuardrailSeverity.High) =>
        new() { IsBlocked = true, Reason = reason, Severity = severity };

    public static GuardrailResult Modified(string modifiedText, string reason) =>
        new() { IsModified = true, ModifiedText = modifiedText, Reason = reason };
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
