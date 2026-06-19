using System.Text.RegularExpressions;

namespace AgentGuard.Pii.Analyzer;

/// <summary>
/// A PII recognizer driven by regular expressions and/or deny-lists, with optional checksum-style
/// validation.
/// </summary>
public class PatternRecognizer : EntityRecognizer
{
    /// <summary>Default regex options: <c>DOTALL | MULTILINE | IGNORECASE</c>.</summary>
    public const RegexOptions DefaultRegexOptions =
        RegexOptions.Singleline | RegexOptions.Multiline | RegexOptions.IgnoreCase | RegexOptions.Compiled;

    /// <summary>Default per-pattern match timeout.</summary>
    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(1);

    private readonly RegexOptions _regexOptions;
    private readonly TimeSpan _timeout;

    /// <summary>Initializes a new instance of the <see cref="PatternRecognizer"/> class.</summary>
    public PatternRecognizer(
        string supportedEntity,
        string? name = null,
        string supportedLanguage = "en",
        IReadOnlyList<Pattern>? patterns = null,
        IReadOnlyList<string>? denyList = null,
        IReadOnlyList<string>? context = null,
        double denyListScore = 1.0,
        RegexOptions regexOptions = DefaultRegexOptions,
        TimeSpan? timeout = null,
        string? countryCode = null)
        : base([supportedEntity], name, supportedLanguage, context, countryCode)
    {
        if (string.IsNullOrEmpty(supportedEntity))
        {
            throw new ArgumentException("Pattern recognizer should be initialized with an entity.", nameof(supportedEntity));
        }

        if ((patterns is null || patterns.Count == 0) && (denyList is null || denyList.Count == 0))
        {
            throw new ArgumentException("Pattern recognizer should be initialized with patterns or with a deny list.");
        }

        _regexOptions = regexOptions;
        _timeout = timeout ?? DefaultTimeout;

        var allPatterns = new List<Pattern>(patterns ?? []);
        if (denyList is { Count: > 0 })
        {
            allPatterns.Add(DenyListToRegex(denyList, denyListScore));
            DenyList = denyList;
        }
        else
        {
            DenyList = [];
        }

        Patterns = allPatterns;
    }

    /// <summary>The entity type this recognizer detects.</summary>
    public string SupportedEntity => SupportedEntities[0];

    /// <summary>The patterns evaluated by this recognizer (deny-list compiled to a pattern is appended).</summary>
    public IReadOnlyList<Pattern> Patterns { get; }

    /// <summary>The configured deny-list words, if any.</summary>
    public IReadOnlyList<string> DenyList { get; }

    /// <inheritdoc />
    public override IReadOnlyList<RecognizerResult> Analyze(string text, IReadOnlyList<string> entities)
    {
        var results = new List<RecognizerResult>();
        if (Patterns.Count > 0)
        {
            results.AddRange(AnalyzePatterns(text));
        }

        return results;
    }

    /// <summary>
    /// Validate a matched string, e.g. via checksum. Return <c>true</c> to snap the score to
    /// <see cref="EntityRecognizer.MaxScore"/>, <c>false</c> to drop the match, or <c>null</c> when not applicable.
    /// </summary>
    public virtual bool? ValidateResult(string patternText) => null;

    /// <summary>
    /// Invalidate a matched string via pruning logic. Return <c>true</c> to drop the match,
    /// or <c>null</c> when not applicable.
    /// </summary>
    public virtual bool? InvalidateResult(string patternText) => null;

    /// <summary>Builds an <see cref="AnalysisExplanation"/> for a regex match.</summary>
    protected AnalysisExplanation BuildRegexExplanation(string patternName, string pattern, double score, bool? validationResult) =>
        new(
            recognizer: Name,
            originalScore: score,
            patternName: patternName,
            pattern: pattern,
            validationResult: validationResult,
            textualExplanation: $"Detected by `{Name}` using pattern `{patternName}`");

    /// <summary>Runs every pattern over the text and returns the surviving results.</summary>
    protected IReadOnlyList<RecognizerResult> AnalyzePatterns(string text)
    {
        var results = new List<RecognizerResult>();
        foreach (var pattern in Patterns)
        {
            var regex = pattern.GetCompiled(_regexOptions, _timeout);
            MatchCollection matches;
            try
            {
                matches = regex.Matches(text);
            }
            catch (RegexMatchTimeoutException)
            {
                continue;
            }

            foreach (Match match in matches)
            {
                if (match.Value.Length == 0)
                {
                    continue;
                }

                var start = match.Index;
                var end = match.Index + match.Length;
                var currentMatch = match.Value;
                var score = pattern.Score;

                var validationResult = ValidateResult(currentMatch);
                var explanation = BuildRegexExplanation(pattern.Name, pattern.Regex, score, validationResult);

                var result = new RecognizerResult(
                    entityType: SupportedEntity,
                    start: start,
                    end: end,
                    score: score,
                    recognitionMetadata: new Dictionary<string, object>
                    {
                        [RecognizerResult.RecognizerNameKey] = Name,
                        [RecognizerResult.RecognizerIdentifierKey] = Id,
                    },
                    analysisExplanation: explanation);

                if (validationResult is not null)
                {
                    result.Score = validationResult.Value ? MaxScore : MinScore;
                }

                var invalidationResult = InvalidateResult(currentMatch);
                if (invalidationResult is true)
                {
                    result.Score = MinScore;
                }

                if (result.Score > MinScore)
                {
                    results.Add(result);
                }

                explanation.Score = result.Score;
            }
        }

        return RemoveDuplicates(results);
    }

    private static Pattern DenyListToRegex(IReadOnlyList<string> denyList, double denyListScore)
    {
        var escaped = denyList.Select(Regex.Escape);
        var regex = @"(?:^|(?<=\W))(" + string.Join("|", escaped) + @")(?:(?=\W)|$)";
        return new Pattern("deny_list", regex, denyListScore);
    }
}
