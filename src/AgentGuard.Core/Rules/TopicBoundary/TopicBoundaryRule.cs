using AgentGuard.Core.Abstractions;

namespace AgentGuard.Core.Rules.TopicBoundary;

public sealed class TopicBoundaryOptions
{
    public IList<string> AllowedTopics { get; init; } = [];
    public float SimilarityThreshold { get; init; } = 0.3f;
    public bool AllowKeywordFallback { get; init; } = true;
    public IDictionary<string, IList<string>> TopicKeywords { get; init; } = new Dictionary<string, IList<string>>();
}

public interface ITopicSimilarityProvider
{
    ValueTask<float> ComputeSimilarityAsync(string input, string topicDescriptor, CancellationToken cancellationToken = default);
}

public sealed class TopicBoundaryRule : IGuardrailRule
{
    private readonly TopicBoundaryOptions _options;
    private readonly ITopicSimilarityProvider? _similarityProvider;

    public TopicBoundaryRule(TopicBoundaryOptions options, ITopicSimilarityProvider? similarityProvider = null)
    { _options = options; _similarityProvider = similarityProvider; }

    public string Name => "topic-boundary";
    public GuardrailPhase Phase => GuardrailPhase.Input;
    public int Order => 30;

    public async ValueTask<GuardrailResult> EvaluateAsync(GuardrailContext context, CancellationToken cancellationToken = default)
    {
        if (_options.AllowedTopics.Count == 0 || string.IsNullOrWhiteSpace(context.Text))
            return GuardrailResult.Passed();

        if (_similarityProvider is not null) return await EvaluateWithEmbeddingsAsync(context.Text, cancellationToken);
        if (_options.AllowKeywordFallback) return EvaluateWithKeywords(context.Text);
        return GuardrailResult.Passed();
    }

    private async ValueTask<GuardrailResult> EvaluateWithEmbeddingsAsync(string text, CancellationToken ct)
    {
        var maxSim = 0f; var bestTopic = "";
        foreach (var topic in _options.AllowedTopics)
        {
            var sim = await _similarityProvider!.ComputeSimilarityAsync(text, topic, ct);
            if (sim > maxSim) { maxSim = sim; bestTopic = topic; }
        }
        return maxSim >= _options.SimilarityThreshold ? GuardrailResult.Passed()
            : GuardrailResult.Blocked($"Input is outside allowed topics. Best match: '{bestTopic}' ({maxSim:P0}).", GuardrailSeverity.Medium);
    }

    private GuardrailResult EvaluateWithKeywords(string text)
    {
        var lower = text.ToLowerInvariant();
        foreach (var topic in _options.AllowedTopics)
        {
            var words = topic.ToLowerInvariant().Split([' ', '-', '_'], StringSplitOptions.RemoveEmptyEntries);
            if (words.Any(w => lower.Contains(w, StringComparison.OrdinalIgnoreCase))) return GuardrailResult.Passed();
        }
        foreach (var (_, keywords) in _options.TopicKeywords)
            if (keywords.Any(k => lower.Contains(k, StringComparison.OrdinalIgnoreCase))) return GuardrailResult.Passed();

        return GuardrailResult.Blocked($"Input does not appear related to allowed topics: {string.Join(", ", _options.AllowedTopics)}.", GuardrailSeverity.Medium);
    }
}
