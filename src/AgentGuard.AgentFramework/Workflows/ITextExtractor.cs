using System.Diagnostics.CodeAnalysis;

namespace AgentGuard.AgentFramework.Workflows;

/// <summary>
/// Extracts a string representation from a typed workflow message for guardrail evaluation, and optionally
/// rebuilds the message from rewritten text.
/// </summary>
/// <remarks>
/// A guarded executor guards chat payloads - <c>ChatMessage</c>, chat message collections and
/// <c>AgentResponse</c> - itself, message by message, without consulting the extractor. It uses the extractor for
/// every other message type, <see cref="string"/> included.
/// </remarks>
public interface ITextExtractor
{
    /// <summary>
    /// Extracts text from an arbitrary workflow message.
    /// Returns null if text cannot be extracted from the given object.
    /// </summary>
    string? ExtractText(object? message);

    /// <summary>
    /// Rebuilds <paramref name="message"/> around rewritten text, so that a guardrail rewrite - a redaction,
    /// for example - reaches the executor. A guarded executor calls this for message types it can't rebuild
    /// on its own. The default implementation rebuilds nothing.
    /// </summary>
    /// <param name="message">The original message.</param>
    /// <param name="text">The rewritten text: what <see cref="ExtractText"/> returned for <paramref name="message"/>, after the rules changed it.</param>
    /// <param name="rebuilt">
    /// The rebuilt message. It must be an instance of the type the executor declares for the message;
    /// otherwise the original message goes on unchanged.
    /// </param>
    /// <returns>
    /// <see langword="true"/> when the message was rebuilt; <see langword="false"/> when this extractor can't
    /// rebuild it, in which case the original message goes on unchanged and a warning is logged.
    /// </returns>
    bool TryRebuild(object message, string text, [NotNullWhen(true)] out object? rebuilt)
    {
        rebuilt = null;
        return false;
    }
}
