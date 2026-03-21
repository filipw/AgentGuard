using AgentGuard.Core.Abstractions;

namespace AgentGuard.Core.Streaming;

/// <summary>
/// The type of output produced by the streaming guardrail pipeline.
/// </summary>
public enum StreamingOutputType
{
    /// <summary>
    /// A text chunk that should be yielded to the consumer.
    /// </summary>
    TextChunk,

    /// <summary>
    /// A guardrail event (retraction or replacement) signaling a mid-stream violation.
    /// </summary>
    GuardrailEvent,

    /// <summary>
    /// The stream has completed. Check <see cref="StreamingPipelineOutput.FinalResult"/>
    /// for any final-check violations.
    /// </summary>
    Completed
}

/// <summary>
/// A single output item from the <see cref="StreamingGuardrailPipeline"/>.
/// Can be a text chunk to yield, a guardrail event (retraction/replacement), or a completion signal.
/// </summary>
public sealed class StreamingPipelineOutput
{
    private StreamingPipelineOutput(StreamingOutputType type, string? text, StreamingGuardrailEvent? guardrailEvent, StreamingFinalResult? finalResult)
    {
        Type = type;
        Text = text;
        GuardrailEvent = guardrailEvent;
        FinalResult = finalResult;
    }

    /// <summary>
    /// The type of this output.
    /// </summary>
    public StreamingOutputType Type { get; }

    /// <summary>
    /// The text chunk (for <see cref="StreamingOutputType.TextChunk"/>).
    /// </summary>
    public string? Text { get; }

    /// <summary>
    /// The guardrail event (for <see cref="StreamingOutputType.GuardrailEvent"/>).
    /// </summary>
    public StreamingGuardrailEvent? GuardrailEvent { get; }

    /// <summary>
    /// The final result after the stream completed (for <see cref="StreamingOutputType.Completed"/>).
    /// </summary>
    public StreamingFinalResult? FinalResult { get; }

    /// <summary>
    /// Creates a text chunk output that should be yielded to the consumer.
    /// </summary>
    public static StreamingPipelineOutput Chunk(string text) =>
        new(StreamingOutputType.TextChunk, text, null, null);

    /// <summary>
    /// Creates a guardrail event output signaling a mid-stream violation.
    /// </summary>
    public static StreamingPipelineOutput Event(StreamingGuardrailEvent guardrailEvent) =>
        new(StreamingOutputType.GuardrailEvent, null, guardrailEvent, null);

    /// <summary>
    /// Creates a completion output.
    /// </summary>
    public static StreamingPipelineOutput Complete(StreamingFinalResult finalResult) =>
        new(StreamingOutputType.Completed, null, null, finalResult);
}

/// <summary>
/// The result of the final guardrail check after the stream has completed.
/// </summary>
public sealed class StreamingFinalResult
{
    private StreamingFinalResult(bool isBlocked, bool wasModified, string? replacementText, GuardrailResult? blockingResult)
    {
        IsBlocked = isBlocked;
        WasModified = wasModified;
        ReplacementText = replacementText;
        BlockingResult = blockingResult;
    }

    /// <summary>
    /// Whether the final check blocked the content.
    /// </summary>
    public bool IsBlocked { get; }

    /// <summary>
    /// Whether the final check modified the content.
    /// </summary>
    public bool WasModified { get; }

    /// <summary>
    /// The replacement text if blocked or modified. UI should retract and show this instead.
    /// </summary>
    public string? ReplacementText { get; }

    /// <summary>
    /// The guardrail result that caused the block, if any.
    /// </summary>
    public GuardrailResult? BlockingResult { get; }

    /// <summary>
    /// Whether the stream passed all guardrails without issue.
    /// </summary>
    public bool Passed => !IsBlocked && !WasModified;

    /// <summary>
    /// Creates a result indicating the stream passed all guardrails.
    /// </summary>
    public static StreamingFinalResult Pass() => new(false, false, null, null);

    /// <summary>
    /// Creates a result indicating the content was blocked at finalization.
    /// </summary>
    public static StreamingFinalResult Blocked(string replacementText, GuardrailResult result) =>
        new(true, false, replacementText, result);

    /// <summary>
    /// Creates a result indicating the content was modified at finalization.
    /// </summary>
    public static StreamingFinalResult Modified(string replacementText) =>
        new(false, true, replacementText, null);
}
