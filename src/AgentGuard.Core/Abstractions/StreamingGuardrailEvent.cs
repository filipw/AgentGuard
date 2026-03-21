namespace AgentGuard.Core.Abstractions;

/// <summary>
/// The type of streaming guardrail event emitted during progressive evaluation.
/// </summary>
public enum StreamingGuardrailEventType
{
    /// <summary>
    /// Signals that previously yielded content should be retracted (hidden/removed by the UI).
    /// Always followed by a <see cref="Replacement"/> event.
    /// </summary>
    Retraction,

    /// <summary>
    /// Provides replacement text to display after a retraction.
    /// </summary>
    Replacement
}

/// <summary>
/// An event emitted during progressive streaming when a guardrail violation is detected
/// after content has already been yielded to the consumer. UI frameworks should handle
/// these events to retract displayed content and show the replacement message.
/// </summary>
/// <remarks>
/// This follows the pattern used by Azure OpenAI content filters: tokens stream through
/// to the user, and if a violation is detected mid-stream, a retraction event signals
/// the UI to hide/replace the partial output already shown.
/// </remarks>
public sealed class StreamingGuardrailEvent
{
    private StreamingGuardrailEvent(StreamingGuardrailEventType type, GuardrailResult? guardrailResult, string? replacementText, int accumulatedTextLength)
    {
        Type = type;
        GuardrailResult = guardrailResult;
        ReplacementText = replacementText;
        AccumulatedTextLength = accumulatedTextLength;
    }

    /// <summary>
    /// The type of event.
    /// </summary>
    public StreamingGuardrailEventType Type { get; }

    /// <summary>
    /// The guardrail result that triggered this event.
    /// </summary>
    public GuardrailResult? GuardrailResult { get; }

    /// <summary>
    /// The replacement text to display (for <see cref="StreamingGuardrailEventType.Replacement"/> events).
    /// </summary>
    public string? ReplacementText { get; }

    /// <summary>
    /// The number of characters that had been yielded to the consumer before this event was emitted.
    /// UI frameworks can use this to determine how much content to retract.
    /// </summary>
    public int AccumulatedTextLength { get; }

    /// <summary>
    /// Creates a retraction event signaling that previously yielded content should be removed.
    /// </summary>
    public static StreamingGuardrailEvent Retract(GuardrailResult result, int accumulatedTextLength) =>
        new(StreamingGuardrailEventType.Retraction, result, null, accumulatedTextLength);

    /// <summary>
    /// Creates a replacement event with the text to display after retraction.
    /// </summary>
    public static StreamingGuardrailEvent Replace(string replacementText, GuardrailResult result, int accumulatedTextLength) =>
        new(StreamingGuardrailEventType.Replacement, result, replacementText, accumulatedTextLength);
}
