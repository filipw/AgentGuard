using System.Text.RegularExpressions;
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
public sealed partial class LlmPiiDetectionRule : LlmGuardrailRule
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
        // Redact mode carries the rewritten message after the verdict marker, so it is read from
        // the raw response rather than reduced to a token. The message can span several lines, and
        // the judge may put it on the lines below the marker. CLEAN, and the PII / CLEAN verdict of
        // Block mode, are read like every other judge verdict.
        if (_options.Action == PiiAction.Redact)
        {
            if (TryReadRedactedMessage(responseText, out var redacted))
            {
                // a judge that fences the message it returns is unwrapped, unless the message it
                // was given was itself a fenced block
                if (!IsFenced(context.Text))
                    redacted = UnwrapFence(redacted);

                if (redacted.Length > 0)
                    return GuardrailResult.Modified(redacted, "LLM classifier redacted personally identifiable information.");

                return UnparseableVerdict(responseText);
            }

            if (ClassifyVerdict(responseText, "PII", "CLEAN", out _) == LlmVerdict.Negative)
                return GuardrailResult.Passed();

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

    private const string RedactedMarker = "REDACTED";

    /// <summary>
    /// Reads the message after a <c>REDACTED:</c> marker that opens the reply. Only the reasoning in
    /// front of the marker is dropped: the message after it is the user's text, returned as the
    /// judge wrote it.
    /// </summary>
    private static bool TryReadRedactedMessage(string responseText, out string message)
    {
        message = "";

        var reply = LeadingReasoningBlocks().Replace(responseText, "");

        // a closing tag in front of the marker means the provider dropped the opening tag; the
        // reasoning ends at the first one, so a closing tag inside the message is left alone
        if (!OpensWithMarker(reply) && ReasoningCloseTag().Match(reply) is { Success: true } closing)
            reply = reply[(closing.Index + closing.Length)..];

        var head = MarkerHead(reply);
        if (!head.StartsWith(RedactedMarker, StringComparison.OrdinalIgnoreCase))
            return false;

        var rest = SkipClosingEmphasis(head[RedactedMarker.Length..]);
        if (rest.StartsWith(':'))
        {
            rest = SkipClosingEmphasis(rest[1..]);
        }
        else
        {
            // without the colon the message must start on the next line ("REDACTED" alone on its line)
            var lineEnd = rest.IndexOf('\n');
            if (!string.IsNullOrWhiteSpace(lineEnd < 0 ? rest : rest[..lineEnd]))
                return false;
        }

        message = rest.Trim();
        return true;
    }

    private static bool OpensWithMarker(string reply)
    {
        var head = MarkerHead(reply);
        return head.StartsWith(RedactedMarker, StringComparison.OrdinalIgnoreCase) || MatchesToken(head, "CLEAN", out _);
    }

    // the start of the reply with a fence, leading emphasis or quoting and a "Verdict:" prefix removed
    private static string MarkerHead(string reply) =>
        TrimLeadingDecoration(TrimVerdictPrefix(TrimLeadingDecoration(UnwrapFence(reply)), out _));

    // emphasis closing the marker ("**REDACTED:**") is skipped; a run that opens the message's own
    // emphasis ("*important*") is part of the message
    private static string SkipClosingEmphasis(string text)
    {
        var end = 0;
        while (end < text.Length && text[end] is '*' or '_' or '`')
            end++;

        return end > 0 && (end == text.Length || text[end] == ':' || char.IsWhiteSpace(text[end]))
            ? text[end..]
            : text;
    }

    private static bool IsFenced(string text) => IsFenceLine(text.TrimStart());

    [GeneratedRegex(@"\A\s*(?:<(think|thinking|reasoning)\b[^>]*>.*?</\1\s*>\s*)+", RegexOptions.Singleline | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex LeadingReasoningBlocks();
}
