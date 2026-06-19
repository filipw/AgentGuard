namespace AgentGuard.Pii.Analyzer;

/// <summary>
/// Holds the decision-process trail for a single <see cref="RecognizerResult"/>: which recognizer
/// and pattern produced it, the original score, and any context-based score adjustment.
/// </summary>
public sealed class AnalysisExplanation
{
    /// <summary>Initializes a new instance of the <see cref="AnalysisExplanation"/> class.</summary>
    public AnalysisExplanation(
        string recognizer,
        double originalScore,
        string? patternName = null,
        string? pattern = null,
        bool? validationResult = null,
        string textualExplanation = "")
    {
        Recognizer = recognizer;
        OriginalScore = originalScore;
        Score = originalScore;
        PatternName = patternName;
        Pattern = pattern;
        ValidationResult = validationResult;
        TextualExplanation = textualExplanation;
    }

    /// <summary>Name of the recognizer that produced the result.</summary>
    public string Recognizer { get; }

    /// <summary>Name of the matching pattern, when produced by a pattern recognizer.</summary>
    public string? PatternName { get; }

    /// <summary>The regex pattern logic, when produced by a pattern recognizer.</summary>
    public string? Pattern { get; }

    /// <summary>The score originally assigned, before any validation or context enhancement.</summary>
    public double OriginalScore { get; }

    /// <summary>The current (possibly enhanced) score.</summary>
    public double Score { get; set; }

    /// <summary>Outcome of recognizer-level validation, when applicable.</summary>
    public bool? ValidationResult { get; }

    /// <summary>Human-readable explanation of the detection.</summary>
    public string TextualExplanation { get; set; }

    /// <summary>The context word that contributed to a score boost, if any.</summary>
    public string SupportiveContextWord { get; private set; } = "";

    /// <summary>The score after context-based enhancement.</summary>
    public double ScoreContextImprovement { get; private set; }

    /// <summary>Records the supportive context word that improved the score.</summary>
    public void SetSupportiveContextWord(string word) => SupportiveContextWord = word;

    /// <summary>Records the improved score after context enhancement.</summary>
    public void SetImprovedScore(double score)
    {
        ScoreContextImprovement = score - Score;
        Score = score;
    }
}
