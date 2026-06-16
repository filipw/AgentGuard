namespace AgentGuard.Pii.Analyzer.Context;

/// <summary>
/// Enhances recognizer result confidence based on context words found near each match.
/// </summary>
public interface IContextAwareEnhancer
{
    /// <summary>
    /// Adjusts the scores of <paramref name="rawResults"/> using context words around each match
    /// and the optional caller-supplied <paramref name="externalContext"/>.
    /// </summary>
    IReadOnlyList<RecognizerResult> EnhanceUsingContext(
        string text,
        IReadOnlyList<RecognizerResult> rawResults,
        IReadOnlyList<EntityRecognizer> recognizers,
        IReadOnlyList<string>? externalContext = null);
}
