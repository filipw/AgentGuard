namespace AgentGuard.Pii.Analyzer;

/// <summary>
/// Represents a single PII entity detected by a recognizer: its type, location in the
/// analyzed text and the recognizer's confidence.
/// </summary>
public sealed class RecognizerResult
{
    /// <summary>Metadata key holding the producing recognizer's name.</summary>
    public const string RecognizerNameKey = "recognizer_name";

    /// <summary>Metadata key holding the producing recognizer's identifier.</summary>
    public const string RecognizerIdentifierKey = "recognizer_identifier";

    /// <summary>Metadata flag set to <c>true</c> once a result's score has been enhanced by context.</summary>
    public const string IsScoreEnhancedByContextKey = "is_score_enhanced_by_context";

    /// <summary>Initializes a new instance of the <see cref="RecognizerResult"/> class.</summary>
    public RecognizerResult(
        string entityType,
        int start,
        int end,
        double score,
        IDictionary<string, object>? recognitionMetadata = null,
        AnalysisExplanation? analysisExplanation = null)
    {
        EntityType = entityType;
        Start = start;
        End = end;
        Score = score;
        RecognitionMetadata = recognitionMetadata;
        AnalysisExplanation = analysisExplanation;
    }

    /// <summary>The detected entity type, e.g. <c>CREDIT_CARD</c>.</summary>
    public string EntityType { get; set; }

    /// <summary>Start offset (inclusive) of the entity in the analyzed text.</summary>
    public int Start { get; set; }

    /// <summary>End offset (exclusive) of the entity in the analyzed text.</summary>
    public int End { get; set; }

    /// <summary>Confidence score in the range [0, 1].</summary>
    public double Score { get; set; }

    /// <summary>Recognizer-specific metadata (e.g. recognizer name/identifier).</summary>
    public IDictionary<string, object>? RecognitionMetadata { get; set; }

    /// <summary>Optional explanation of how this result was produced and scored.</summary>
    public AnalysisExplanation? AnalysisExplanation { get; set; }

    /// <summary>
    /// Returns the number of overlapping characters with <paramref name="other"/>, or 0 if disjoint.
    /// </summary>
    public int Intersects(RecognizerResult other)
    {
        if (End < other.Start || other.End < Start)
        {
            return 0;
        }

        return Math.Min(End, other.End) - Math.Max(Start, other.Start);
    }

    /// <summary>Returns <c>true</c> if this result is fully contained in <paramref name="other"/>.</summary>
    public bool ContainedIn(RecognizerResult other) => Start >= other.Start && End <= other.End;

    /// <summary>Returns <c>true</c> if this result fully contains <paramref name="other"/>.</summary>
    public bool Contains(RecognizerResult other) => Start <= other.Start && End >= other.End;

    /// <summary>Returns <c>true</c> if both results span the exact same indices.</summary>
    public bool EqualIndices(RecognizerResult other) => Start == other.Start && End == other.End;

    /// <summary>
    /// Returns <c>true</c> if this result conflicts with <paramref name="other"/>: same indices but
    /// lower-or-equal score, or contained within the other.
    /// </summary>
    public bool HasConflict(RecognizerResult other)
    {
        if (EqualIndices(other))
        {
            return Score <= other.Score;
        }

        return other.Contains(this);
    }

    /// <inheritdoc />
    public override string ToString() =>
        $"type: {EntityType}, start: {Start}, end: {End}, score: {Score}";
}
