namespace AgentGuard.AgentFramework.Workflows;

/// <summary>
/// Extracts a string representation from a typed workflow message for guardrail evaluation.
/// </summary>
public interface ITextExtractor
{
    /// <summary>
    /// Extracts text from an arbitrary workflow message.
    /// Returns null if text cannot be extracted from the given object.
    /// </summary>
    string? ExtractText(object? message);
}
