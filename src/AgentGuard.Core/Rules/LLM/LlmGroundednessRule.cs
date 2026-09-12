using AgentGuard.Core.Abstractions;
using Microsoft.Extensions.AI;

namespace AgentGuard.Core.Rules.LLM;

/// <summary>
/// What to do when an ungrounded claim is detected.
/// </summary>
public enum GroundednessAction
{
    /// <summary>Block the response entirely.</summary>
    Block,
    /// <summary>Allow the response but attach ungrounded claim metadata for downstream handling.</summary>
    Warn
}

/// <summary>
/// Options for LLM-based groundedness checking.
/// </summary>
public sealed class LlmGroundednessOptions
{
    /// <summary>
    /// Action to take when an ungrounded claim is detected. Defaults to <see cref="GroundednessAction.Block"/>.
    /// </summary>
    public GroundednessAction Action { get; init; } = GroundednessAction.Block;

    /// <summary>
    /// Optional custom system prompt override. If null, the built-in prompt template is used.
    /// Use {context} as a placeholder for the formatted conversation history.
    /// </summary>
    public string? SystemPrompt { get; init; }
}

/// <summary>
/// Checks whether an agent's response is grounded in the conversation context using an LLM classifier.
/// Detects hallucinated facts, fabricated data, and claims not supported by the conversation history.
/// </summary>
public sealed class LlmGroundednessRule : LlmGuardrailRule
{
    private readonly LlmGroundednessOptions _options;

    /// <summary>Initializes a new instance of the <see cref="LlmGroundednessRule"/> class.</summary>
    /// <param name="chatClient">The client used to call the judge model.</param>
    /// <param name="options">Action and prompt override.</param>
    /// <param name="chatOptions">Optional options for the judge call.</param>
    /// <param name="errorBehavior">What to do when the judge fails or returns an off-format verdict.</param>
    public LlmGroundednessRule(IChatClient chatClient, LlmGroundednessOptions? options = null, ChatOptions? chatOptions = null, ErrorBehavior errorBehavior = ErrorBehavior.FailOpen)
        : base(chatClient, chatOptions, errorBehavior)
    {
        _options = options ?? new();
    }

    /// <inheritdoc />
    public override string Name => "llm-groundedness";
    /// <inheritdoc />
    public override GuardrailPhase Phase => GuardrailPhase.Output;
    /// <inheritdoc />
    public override int Order => 65;

    private const string DefaultSystemPromptTemplate =
        """
        You are a groundedness evaluator. Your task is to determine whether an AI assistant's response
        is grounded in the provided conversation context.

        A response is grounded if all factual claims, data points, and specific assertions it makes
        can be traced back to information present in the conversation history or are common knowledge.
        A response is ungrounded if it fabricates specific facts, invents data, or makes claims that
        contradict or go beyond what the conversation history supports.

        General knowledge statements, reasoning, and opinions do not need to be grounded in the
        conversation history.

        ## Conversation history
        {context}

        Analyze the following response for groundedness. Respond in exactly one of these formats:
        - GROUNDED if all claims in the response are supported by the conversation context or are common knowledge
        - UNGROUNDED|claim:<the specific ungrounded claim> if the response contains fabricated or unsupported claims

        Do not explain your reasoning beyond the claim field. Respond with only the verdict line.
        """;

    /// <inheritdoc />
    protected override IEnumerable<ChatMessage> BuildPrompt(GuardrailContext context)
    {
        var conversationHistory = FormatConversationHistory(
            context.Messages, heading: null, emptyPlaceholder: "(no conversation history available)");
        var systemPrompt = _options.SystemPrompt?.Replace("{context}", conversationHistory)
            ?? DefaultSystemPromptTemplate.Replace("{context}", conversationHistory);

        return
        [
            new(ChatRole.System, systemPrompt),
            new(ChatRole.User, context.Text)
        ];
    }

    /// <inheritdoc />
    protected override GuardrailResult ParseResponse(string responseText, GuardrailContext context)
    {
        var verdict = ClassifyVerdict(responseText, "UNGROUNDED", "GROUNDED", out var verdictLine);

        if (verdict == LlmVerdict.Negative)
            return GuardrailResult.Passed();

        if (verdict == LlmVerdict.Unparseable)
            return UnparseableVerdict(responseText);

        var claim = ParseClaim(verdictLine);

        if (_options.Action == GroundednessAction.Warn)
        {
            return new GuardrailResult
            {
                IsBlocked = false,
                Metadata = new Dictionary<string, object>
                {
                    ["ungrounded_claim"] = claim
                }
            };
        }

        return new GuardrailResult
        {
            IsBlocked = true,
            Reason = $"Response contains ungrounded claim: {claim}",
            Severity = GuardrailSeverity.Medium,
            Metadata = new Dictionary<string, object>
            {
                ["ungrounded_claim"] = claim
            }
        };
    }

    internal static string ParseClaim(string response)
    {
        var parts = response.Split('|', StringSplitOptions.RemoveEmptyEntries);
        foreach (var part in parts.Skip(1))
        {
            var kv = part.Split(':', 2, StringSplitOptions.TrimEntries);
            if (kv.Length == 2 && kv[0].Equals("claim", StringComparison.OrdinalIgnoreCase))
                return kv[1];
        }

        return "Ungrounded content detected.";
    }

}
