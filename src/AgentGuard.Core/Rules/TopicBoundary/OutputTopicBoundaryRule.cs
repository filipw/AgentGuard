using AgentGuard.Core.Abstractions;

namespace AgentGuard.Core.Rules.TopicBoundary;

/// <summary>
/// Options for output topic boundary enforcement.
/// </summary>
public sealed class OutputTopicBoundaryOptions
{
    /// <summary>
    /// The topics that the agent's response is allowed to cover.
    /// </summary>
    public IList<string> AllowedTopics { get; init; } = [];

    /// <summary>
    /// Minimum cosine similarity score to consider a response on-topic.
    /// Defaults to 0.3. Lower values are more permissive.
    /// </summary>
    public float SimilarityThreshold { get; init; } = 0.3f;

    /// <summary>
    /// Whether to fall back to keyword matching when no similarity provider is available.
    /// Defaults to true.
    /// </summary>
    public bool AllowKeywordFallback { get; init; } = true;

    /// <summary>
    /// Optional keyword overrides per topic. Used only when <see cref="AllowKeywordFallback"/> is true
    /// and no <see cref="ITopicSimilarityProvider"/> is available.
    /// </summary>
    public IDictionary<string, IList<string>> TopicKeywords { get; init; } = new Dictionary<string, IList<string>>();

    /// <summary>
    /// Action to take when the response is off-topic. Defaults to <see cref="OutputTopicAction.Block"/>.
    /// </summary>
    public OutputTopicAction Action { get; init; } = OutputTopicAction.Block;
}

/// <summary>
/// What to do when the agent's response drifts off-topic.
/// </summary>
public enum OutputTopicAction
{
    /// <summary>Block the response entirely.</summary>
    Block,
    /// <summary>Allow the response but attach off-topic metadata for downstream handling.</summary>
    Warn
}

/// <summary>
/// Checks whether an agent's response stays within allowed topic boundaries using embedding similarity
/// or keyword fallback. Runs on the output phase to catch topic drift in agent responses.
/// This is the output counterpart to <see cref="TopicBoundaryRule"/> (which validates input).
/// </summary>
public sealed class OutputTopicBoundaryRule : IGuardrailRule
{
    private readonly OutputTopicBoundaryOptions _options;
    private readonly ITopicSimilarityProvider? _similarityProvider;

    /// <summary>
    /// Creates a new output topic boundary rule.
    /// </summary>
    /// <param name="options">Configuration options.</param>
    /// <param name="similarityProvider">
    /// Optional embedding-based similarity provider. When null and <see cref="OutputTopicBoundaryOptions.AllowKeywordFallback"/>
    /// is true, falls back to keyword matching.
    /// </param>
    public OutputTopicBoundaryRule(OutputTopicBoundaryOptions options, ITopicSimilarityProvider? similarityProvider = null)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _similarityProvider = similarityProvider;
    }

    /// <inheritdoc />
    public string Name => "output-topic-boundary";

    /// <inheritdoc />
    public GuardrailPhase Phase => GuardrailPhase.Output;

    /// <inheritdoc />
    public int Order => 60;

    /// <inheritdoc />
    public async ValueTask<GuardrailResult> EvaluateAsync(GuardrailContext context, CancellationToken cancellationToken = default)
    {
        if (_options.AllowedTopics.Count == 0 || string.IsNullOrWhiteSpace(context.Text))
            return GuardrailResult.Passed();

        if (_similarityProvider is not null)
            return await EvaluateWithEmbeddingsAsync(context.Text, cancellationToken);

        if (_options.AllowKeywordFallback)
            return EvaluateWithKeywords(context.Text);

        return GuardrailResult.Passed();
    }

    private async ValueTask<GuardrailResult> EvaluateWithEmbeddingsAsync(string text, CancellationToken ct)
    {
        var maxSim = 0f;
        var bestTopic = "";

        foreach (var topic in _options.AllowedTopics)
        {
            var sim = await _similarityProvider!.ComputeSimilarityAsync(text, topic, ct);
            if (sim > maxSim)
            {
                maxSim = sim;
                bestTopic = topic;
            }
        }

        if (maxSim >= _options.SimilarityThreshold)
            return GuardrailResult.Passed();

        return CreateOffTopicResult(bestTopic, maxSim);
    }

    private GuardrailResult EvaluateWithKeywords(string text)
    {
        var lower = text.ToLowerInvariant();

        foreach (var topic in _options.AllowedTopics)
        {
            var words = topic.ToLowerInvariant().Split([' ', '-', '_'], StringSplitOptions.RemoveEmptyEntries);
            if (words.Any(w => lower.Contains(w, StringComparison.OrdinalIgnoreCase)))
                return GuardrailResult.Passed();
        }

        foreach (var (_, keywords) in _options.TopicKeywords)
        {
            if (keywords.Any(k => lower.Contains(k, StringComparison.OrdinalIgnoreCase)))
                return GuardrailResult.Passed();
        }

        return CreateOffTopicResult(null, null);
    }

    private GuardrailResult CreateOffTopicResult(string? bestTopic, float? similarity)
    {
        var reason = bestTopic is not null && similarity.HasValue
            ? $"Response drifted outside allowed topics. Best match: '{bestTopic}' ({similarity.Value:P0})."
            : $"Response does not appear related to allowed topics: {string.Join(", ", _options.AllowedTopics)}.";

        var metadata = new Dictionary<string, object>
        {
            ["allowed_topics"] = string.Join(", ", _options.AllowedTopics)
        };

        if (bestTopic is not null)
            metadata["best_match_topic"] = bestTopic;

        if (similarity.HasValue)
            metadata["best_match_similarity"] = similarity.Value;

        if (_options.Action == OutputTopicAction.Warn)
        {
            return new GuardrailResult
            {
                IsBlocked = false,
                Reason = reason,
                Metadata = metadata
            };
        }

        return new GuardrailResult
        {
            IsBlocked = true,
            Reason = reason,
            Severity = GuardrailSeverity.Medium,
            Metadata = metadata
        };
    }
}
