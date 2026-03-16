using AgentGuard.Core.Abstractions;
using Microsoft.Extensions.AI;

namespace AgentGuard.Core.Rules.LLM;

/// <summary>
/// Options for LLM-based topic boundary enforcement.
/// </summary>
public sealed class LlmTopicGuardrailOptions
{
    /// <summary>
    /// The allowed topics. The LLM will be asked to classify whether the input fits these topics.
    /// </summary>
    public required IList<string> AllowedTopics { get; init; }

    /// <summary>
    /// Optional custom system prompt override. If null, the built-in prompt template is used.
    /// Use {topics} as a placeholder for the allowed topics list.
    /// </summary>
    public string? SystemPrompt { get; init; }
}

/// <summary>
/// Enforces topic boundaries using an LLM classifier.
/// More accurate than keyword matching — understands semantic meaning and intent.
/// </summary>
public sealed class LlmTopicGuardrailRule : LlmGuardrailRule
{
    private readonly LlmTopicGuardrailOptions _options;
    private readonly string _systemPrompt;

    public LlmTopicGuardrailRule(IChatClient chatClient, LlmTopicGuardrailOptions options)
        : base(chatClient)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        var topicsList = string.Join(", ", _options.AllowedTopics);
        _systemPrompt = _options.SystemPrompt?.Replace("{topics}", topicsList) ?? GetDefaultPrompt(topicsList);
    }

    public override string Name => "llm-topic-boundary";
    public override GuardrailPhase Phase => GuardrailPhase.Input;
    public override int Order => 35;

    internal static string GetDefaultPrompt(string topicsList) =>
        $"""
        You are a topic classification system. Your task is to determine whether a user message falls within
        the allowed topics for this agent.

        Allowed topics: {topicsList}

        Interpret the allowed topics broadly — if the user's message is reasonably related to any allowed topic,
        it should be considered on-topic. Only flag messages that are clearly unrelated to all allowed topics.

        Respond with exactly one word:
        - ON_TOPIC if the message is related to any of the allowed topics
        - OFF_TOPIC if the message is clearly unrelated to all allowed topics

        Do not explain your reasoning. Respond with only ON_TOPIC or OFF_TOPIC.
        """;

    protected override IEnumerable<ChatMessage> BuildPrompt(GuardrailContext context) =>
    [
        new(ChatRole.System, _systemPrompt),
        new(ChatRole.User, context.Text)
    ];

    protected override GuardrailResult ParseResponse(string responseText, GuardrailContext context)
    {
        var trimmed = responseText.Trim().ToUpperInvariant();

        if (trimmed.Contains("OFF_TOPIC"))
        {
            var topicsList = string.Join(", ", _options.AllowedTopics);
            return GuardrailResult.Blocked(
                $"Message is outside the allowed topics ({topicsList}).",
                GuardrailSeverity.Medium);
        }

        return GuardrailResult.Passed();
    }
}
