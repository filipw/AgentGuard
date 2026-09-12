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
/// More accurate than keyword matching - understands semantic meaning and intent.
/// </summary>
public sealed class LlmTopicGuardrailRule : LlmGuardrailRule
{
    private readonly LlmTopicGuardrailOptions _options;
    private readonly string _systemPrompt;

    /// <summary>Initializes a new instance of the <see cref="LlmTopicGuardrailRule"/> class.</summary>
    /// <param name="chatClient">The client used to call the judge model.</param>
    /// <param name="options">Allowed topics and prompt override.</param>
    /// <param name="chatOptions">Optional options for the judge call.</param>
    /// <param name="errorBehavior">What to do when the judge fails or returns an off-format verdict.</param>
    public LlmTopicGuardrailRule(IChatClient chatClient, LlmTopicGuardrailOptions options, ChatOptions? chatOptions = null, ErrorBehavior errorBehavior = ErrorBehavior.FailOpen)
        : base(chatClient, chatOptions, errorBehavior)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        var topicsList = string.Join(", ", _options.AllowedTopics);
        _systemPrompt = _options.SystemPrompt?.Replace("{topics}", topicsList) ?? GetDefaultPrompt(topicsList);
    }

    /// <inheritdoc />
    public override string Name => "llm-topic-boundary";
    /// <inheritdoc />
    public override GuardrailPhase Phase => GuardrailPhase.Input;
    /// <inheritdoc />
    public override int Order => 35;

    internal static string GetDefaultPrompt(string topicsList) =>
        $$"""
        You are a topic classification system. Your task is to determine whether a user message falls within
        the allowed topics for this agent, considering the full conversation context.

        Allowed topics: {{topicsList}}

        Interpret the allowed topics broadly - if the user's message is reasonably related to any allowed topic,
        it should be considered on-topic. Only flag messages that are clearly unrelated to all allowed topics.

        Important: evaluate the LATEST user message in the context of the conversation history.
        Short replies like "yes", "no", "that's correct", "tell me more" are on-topic if the preceding
        conversation is on-topic. Only flag messages that introduce a clearly unrelated subject.

        {history}

        Respond with exactly one word:
        - ON_TOPIC if the message is related to any of the allowed topics
        - OFF_TOPIC if the message is clearly unrelated to all allowed topics

        Do not explain your reasoning. Respond with only ON_TOPIC or OFF_TOPIC.
        """;

    /// <inheritdoc />
    protected override IEnumerable<ChatMessage> BuildPrompt(GuardrailContext context)
    {
        var history = FormatConversationHistory(context.Messages);
        var prompt = _systemPrompt.Replace("{history}", history);
        return
        [
            new(ChatRole.System, prompt),
            new(ChatRole.User, context.Text)
        ];
    }


    /// <inheritdoc />
    protected override GuardrailResult ParseResponse(string responseText, GuardrailContext context)
    {
        var verdict = ClassifyVerdict(responseText, "OFF_TOPIC", "ON_TOPIC", out _);

        return verdict switch
        {
            LlmVerdict.Negative => GuardrailResult.Passed(),
            LlmVerdict.Unparseable => UnparseableVerdict(responseText),
            _ => GuardrailResult.Blocked(
                $"Message is outside the allowed topics ({string.Join(", ", _options.AllowedTopics)}).",
                GuardrailSeverity.Medium)
        };
    }
}
