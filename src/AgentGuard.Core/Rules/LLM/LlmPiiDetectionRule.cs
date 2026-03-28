using AgentGuard.Core.Abstractions;
using Microsoft.Extensions.AI;

namespace AgentGuard.Core.Rules.LLM;

/// <summary>
/// Options for LLM-based PII detection.
/// </summary>
public sealed class LlmPiiDetectionOptions
{
    /// <summary>
    /// Action to take when PII is detected. Defaults to <see cref="PiiAction.Redact"/>.
    /// </summary>
    public PiiAction Action { get; init; } = PiiAction.Redact;

    /// <summary>
    /// Optional custom system prompt override. If null, the built-in prompt template is used.
    /// </summary>
    public string? SystemPrompt { get; init; }
}

/// <summary>
/// What to do when PII is detected.
/// </summary>
public enum PiiAction
{
    /// <summary>Block the message entirely.</summary>
    Block,
    /// <summary>Ask the LLM to return a redacted version.</summary>
    Redact
}

/// <summary>
/// Detects and optionally redacts PII using an LLM classifier.
/// More accurate than regex-based detection for unstructured PII like names, addresses, and contextual identifiers.
/// </summary>
public sealed class LlmPiiDetectionRule : LlmGuardrailRule
{
    private readonly LlmPiiDetectionOptions _options;
    private readonly string _systemPrompt;

    public LlmPiiDetectionRule(IChatClient chatClient, LlmPiiDetectionOptions? options = null, ChatOptions? chatOptions = null, ErrorBehavior errorBehavior = ErrorBehavior.FailOpen)
        : base(chatClient, chatOptions, errorBehavior)
    {
        _options = options ?? new();
        _systemPrompt = _options.SystemPrompt ?? GetDefaultPrompt(_options.Action);
    }

    public override string Name => "llm-pii-detection";
    public override GuardrailPhase Phase => GuardrailPhase.Both;
    public override int Order => 25;

    internal static string GetDefaultPrompt(PiiAction action) => action switch
    {
        PiiAction.Block =>
            """
            You are a PII detection classifier. Analyze the user message for personally identifiable information (PII).

            PII includes: full names, email addresses, phone numbers, physical addresses, social security numbers,
            credit card numbers, bank account numbers, passport numbers, driver's license numbers, dates of birth,
            IP addresses, medical record numbers, biometric data references, and any other information that could
            identify a specific individual.

            Respond with exactly one word:
            - CLEAN if the message contains no PII
            - PII if the message contains any personally identifiable information

            Do not explain your reasoning. Respond with only CLEAN or PII.
            """,

        PiiAction.Redact =>
            """
            You are a PII redaction system. Analyze the user message for personally identifiable information (PII).

            PII includes: full names, email addresses, phone numbers, physical addresses, social security numbers,
            credit card numbers, bank account numbers, passport numbers, driver's license numbers, dates of birth,
            IP addresses, medical record numbers, biometric data references, and any other information that could
            identify a specific individual.

            If the message contains NO PII, respond with exactly:
            CLEAN

            If the message contains PII, respond with exactly:
            REDACTED: <the original message with all PII replaced by [REDACTED]>

            Do not explain your reasoning. Do not add any other text.
            """,

        _ => throw new ArgumentOutOfRangeException(nameof(action))
    };

    protected override IEnumerable<ChatMessage> BuildPrompt(GuardrailContext context) =>
    [
        new(ChatRole.System, _systemPrompt),
        new(ChatRole.User, context.Text)
    ];

    protected override GuardrailResult ParseResponse(string responseText, GuardrailContext context)
    {
        var trimmed = responseText.Trim();
        var upper = trimmed.ToUpperInvariant();

        if (upper.StartsWith("CLEAN", StringComparison.Ordinal))
            return GuardrailResult.Passed();

        if (_options.Action == PiiAction.Block && upper.Contains("PII", StringComparison.Ordinal))
            return GuardrailResult.Blocked("LLM classifier detected personally identifiable information.", GuardrailSeverity.High);

        if (_options.Action == PiiAction.Redact && upper.StartsWith("REDACTED:", StringComparison.Ordinal))
        {
            var redacted = trimmed["REDACTED:".Length..].TrimStart();
            if (!string.IsNullOrEmpty(redacted))
                return GuardrailResult.Modified(redacted, "LLM classifier redacted personally identifiable information.");
        }

        // If we can't parse the response cleanly, check for PII keyword as fallback
        if (upper.Contains("PII", StringComparison.Ordinal) || upper.Contains("REDACTED", StringComparison.Ordinal))
            return GuardrailResult.Blocked("LLM classifier detected personally identifiable information.", GuardrailSeverity.High);

        return GuardrailResult.Passed();
    }
}
