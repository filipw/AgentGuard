using AgentGuard.Core.Abstractions;
using Microsoft.Extensions.AI;

namespace AgentGuard.Core.Rules.LLM;

/// <summary>
/// What to do when copyrighted material is detected in the response.
/// </summary>
public enum CopyrightAction
{
    /// <summary>Block the response entirely.</summary>
    Block,
    /// <summary>Allow the response but attach copyright detection metadata for downstream handling.</summary>
    Warn
}

/// <summary>
/// Options for LLM-based copyright detection.
/// </summary>
public sealed class LlmCopyrightOptions
{
    /// <summary>
    /// Action to take when copyrighted material is detected. Defaults to <see cref="CopyrightAction.Block"/>.
    /// </summary>
    public CopyrightAction Action { get; init; } = CopyrightAction.Block;

    /// <summary>
    /// Optional custom system prompt override. If null, the built-in prompt template is used.
    /// </summary>
    public string? SystemPrompt { get; init; }
}

/// <summary>
/// Detects whether an agent's response reproduces copyrighted material using an LLM classifier.
/// Catches verbatim or near-verbatim reproduction of song lyrics, book passages, articles,
/// restrictively-licensed code, and other protected works.
/// </summary>
public sealed class LlmCopyrightRule : LlmGuardrailRule
{
    private readonly LlmCopyrightOptions _options;
    private readonly string _systemPrompt;

    /// <summary>Initializes a new instance of the <see cref="LlmCopyrightRule"/> class.</summary>
    /// <param name="chatClient">The client used to call the judge model.</param>
    /// <param name="options">Action and prompt override.</param>
    /// <param name="chatOptions">Optional options for the judge call.</param>
    /// <param name="errorBehavior">What to do when the judge fails or returns an off-format verdict.</param>
    public LlmCopyrightRule(IChatClient chatClient, LlmCopyrightOptions? options = null, ChatOptions? chatOptions = null, ErrorBehavior errorBehavior = ErrorBehavior.FailOpen)
        : base(chatClient, chatOptions, errorBehavior)
    {
        _options = options ?? new();
        _systemPrompt = _options.SystemPrompt ?? DefaultSystemPrompt;
    }

    /// <inheritdoc />
    public override string Name => "llm-copyright";
    /// <inheritdoc />
    public override GuardrailPhase Phase => GuardrailPhase.Output;
    /// <inheritdoc />
    public override int Order => 75;

    internal const string DefaultSystemPrompt =
        """
        You are a copyright detection system. Your task is to determine whether an AI assistant's response
        reproduces copyrighted material.

        Check for:
        - Verbatim or near-verbatim reproduction of song lyrics (more than a short phrase)
        - Extended passages from books, novels, or short stories
        - Substantial portions of news articles or journal papers
        - Code copied from projects with restrictive licenses (GPL, AGPL, proprietary)
        - Verbatim reproduction of poems, speeches, or screenplays

        The following are acceptable and should NOT be flagged:
        - Short factual quotes (under approximately 15 words) used for commentary or reference
        - Common phrases, idioms, and proverbs
        - Public domain works
        - Facts, ideas, and concepts (copyright protects expression, not ideas)
        - Original content that discusses or references copyrighted works without reproducing them

        Respond in exactly one of these formats:
        - CLEAN if the response does not reproduce copyrighted material
        - COPYRIGHT|source:<likely source work or author>|type:<lyrics|book|article|code|poem|speech|other>
          if the response reproduces copyrighted material

        Do not explain your reasoning beyond the source and type fields. Respond with only the verdict line.
        """;

    /// <inheritdoc />
    protected override IEnumerable<ChatMessage> BuildPrompt(GuardrailContext context) =>
    [
        new(ChatRole.System, _systemPrompt),
        new(ChatRole.User, context.Text)
    ];

    /// <inheritdoc />
    protected override GuardrailResult ParseResponse(string responseText, GuardrailContext context)
    {
        var verdict = ClassifyVerdict(responseText, "COPYRIGHT", "CLEAN", out var verdictLine);

        if (verdict == LlmVerdict.Negative)
            return GuardrailResult.Passed();

        if (verdict == LlmVerdict.Unparseable)
            return UnparseableVerdict(responseText);

        var (source, type) = ParseFields(verdictLine);

        var metadata = new Dictionary<string, object>
        {
            ["copyright_source"] = source,
            ["copyright_type"] = type
        };

        if (_options.Action == CopyrightAction.Warn)
        {
            return new GuardrailResult
            {
                IsBlocked = false,
                Metadata = metadata
            };
        }

        return new GuardrailResult
        {
            IsBlocked = true,
            Reason = $"Response may reproduce copyrighted material from: {source} ({type}).",
            Severity = GuardrailSeverity.High,
            Metadata = metadata
        };
    }

    internal static (string source, string type) ParseFields(string response)
    {
        var source = "unknown";
        var type = "unknown";
        var parts = response.Split('|', StringSplitOptions.RemoveEmptyEntries);

        foreach (var part in parts.Skip(1))
        {
            var kv = part.Split(':', 2, StringSplitOptions.TrimEntries);
            if (kv.Length == 2 && !string.IsNullOrEmpty(kv[1]))
            {
                if (kv[0].Equals("source", StringComparison.OrdinalIgnoreCase))
                    source = kv[1];
                else if (kv[0].Equals("type", StringComparison.OrdinalIgnoreCase))
                    type = kv[1];
            }
        }

        return (source, type);
    }
}
