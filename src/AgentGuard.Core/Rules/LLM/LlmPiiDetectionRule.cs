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

    /// <summary>Initializes a new instance of the <see cref="LlmPiiDetectionRule"/> class.</summary>
    /// <param name="chatClient">The client used to call the judge model.</param>
    /// <param name="options">Action (block or redact) and prompt override.</param>
    /// <param name="chatOptions">Optional options for the judge call.</param>
    /// <param name="errorBehavior">What to do when the judge fails or returns an off-format verdict.</param>
    public LlmPiiDetectionRule(IChatClient chatClient, LlmPiiDetectionOptions? options = null, ChatOptions? chatOptions = null, ErrorBehavior errorBehavior = ErrorBehavior.FailOpen)
        : base(chatClient, chatOptions, errorBehavior)
    {
        _options = options ?? new();
        _systemPrompt = _options.SystemPrompt ?? GetDefaultPrompt(_options.Action);
    }

    /// <inheritdoc />
    public override string Name => "llm-pii-detection";
    /// <inheritdoc />
    public override GuardrailPhase Phase => GuardrailPhase.Both;
    /// <inheritdoc />
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

    /// <inheritdoc />
    protected override IEnumerable<ChatMessage> BuildPrompt(GuardrailContext context) =>
    [
        new(ChatRole.System, _systemPrompt),
        new(ChatRole.User, context.Text)
    ];

    /// <inheritdoc />
    protected override GuardrailResult ParseResponse(string responseText, GuardrailContext context)
    {
        // Redact mode carries the rewritten message on the verdict line, so it is read from the raw
        // response rather than reduced to a token.
        if (_options.Action == PiiAction.Redact)
        {
            var line = ExtractVerdictLine(responseText);

            if (line.StartsWith("CLEAN", StringComparison.OrdinalIgnoreCase))
                return GuardrailResult.Passed();

            if (line.StartsWith(RedactedPrefix, StringComparison.OrdinalIgnoreCase))
            {
                var redacted = line[RedactedPrefix.Length..].TrimStart();
                if (redacted.Length > 0)
                    return GuardrailResult.Modified(redacted, "LLM classifier redacted personally identifiable information.");
            }

            // a rule configured to redact must never silently turn into a block because the word
            // "REDACTED" appeared somewhere in an off-format reply.
            return UnparseableVerdict(responseText);
        }

        var verdict = ClassifyVerdict(responseText, "PII", "CLEAN", out _);

        return verdict switch
        {
            LlmVerdict.Negative => GuardrailResult.Passed(),
            LlmVerdict.Unparseable => UnparseableVerdict(responseText),
            _ => GuardrailResult.Blocked(
                "LLM classifier detected personally identifiable information.", GuardrailSeverity.High)
        };
    }

    private const string RedactedPrefix = "REDACTED:";
}
