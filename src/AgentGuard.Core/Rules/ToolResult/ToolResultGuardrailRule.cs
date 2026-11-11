using System.Text;
using System.Text.RegularExpressions;
using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Rules.Normalization;

namespace AgentGuard.Core.Rules.ToolResult;

/// <summary>
/// Risk level assigned to a tool based on the type of data it returns.
/// Higher risk tools are more likely to contain indirect prompt injection.
/// </summary>
public enum ToolRiskLevel
{
    /// <summary>Low risk - structured data, internal APIs.</summary>
    Low = 0,

    /// <summary>Medium risk - documents, code, CRM data.</summary>
    Medium = 1,

    /// <summary>High risk - email, messaging, user-generated content.</summary>
    High = 2
}

/// <summary>
/// Action to take when indirect injection is detected in a tool result.
/// </summary>
public enum ToolResultAction
{
    /// <summary>Block the entire pipeline.</summary>
    Block,

    /// <summary>
    /// Sanitize the tool result by removing the detected injection. A match only marks where an
    /// injected instruction starts, so everything from the start of the matched line through the
    /// end of its paragraph (the next blank line, or the end of the content) is replaced with
    /// <see cref="ToolResultGuardrailOptions.SanitizationReplacement"/>. Content with no paragraph
    /// breaks loses everything from the matched line on; use <see cref="Block"/> when precision
    /// matters more than keeping the rest of the result. An injection found inside an encoded run
    /// (see <see cref="ToolResultGuardrailOptions.DetectEncodedPayloads"/>) has a known extent, so
    /// only that run is replaced and the text around it is kept.
    /// </summary>
    Sanitize
}

/// <summary>
/// Represents a tool result returned to the agent that should be inspected for indirect injection.
/// </summary>
public sealed class ToolResultEntry
{
    /// <summary>The name of the tool that produced this result.</summary>
    public required string ToolName { get; init; }

    /// <summary>The content returned by the tool.</summary>
    public required string Content { get; init; }

    /// <summary>
    /// Optional risk level override. If not set, the rule will use tool risk profiles
    /// or default to <see cref="ToolRiskLevel.Medium"/>.
    /// </summary>
    public ToolRiskLevel? RiskLevel { get; init; }

    /// <summary>Optional metadata about the tool result (e.g. source, timestamp).</summary>
    public IReadOnlyDictionary<string, object>? Metadata { get; init; }
}

/// <summary>
/// A detected injection in a tool result.
/// </summary>
public sealed class ToolResultViolation
{
    /// <summary>The tool name that returned the injected content.</summary>
    public required string ToolName { get; init; }

    /// <summary>The category of injection detected.</summary>
    public required string Category { get; init; }

    /// <summary>Description of the detected pattern.</summary>
    public required string Description { get; init; }

    /// <summary>The matched text fragment (truncated to 100 chars); decoded when <see cref="Encoding"/> is set.</summary>
    public string? MatchedText { get; init; }

    /// <summary>
    /// How the injection was encoded in the tool result - <c>base64</c> (base64url included),
    /// <c>hex</c> or <c>percent</c> - when it was found in decoded content (see
    /// <see cref="ToolResultGuardrailOptions.DetectEncodedPayloads"/>); <c>null</c> when it was
    /// found in the text as returned. <see cref="Description"/> names the encoding too.
    /// </summary>
    public string? Encoding { get; init; }
}

/// <summary>
/// Options for the tool result guardrail rule.
/// </summary>
public sealed class ToolResultGuardrailOptions
{
    /// <summary>
    /// Action to take when injection is detected. Default: Block.
    /// </summary>
    public ToolResultAction Action { get; init; } = ToolResultAction.Block;

    /// <summary>
    /// Tool-specific risk profiles. Key is tool name (case-insensitive), value is risk level.
    /// Tools at <see cref="ToolRiskLevel.Low"/> are checked with fewer patterns.
    /// Default: empty (all tools use <see cref="ToolRiskLevel.Medium"/>).
    /// </summary>
    public IDictionary<string, ToolRiskLevel> ToolRiskProfiles { get; init; } =
        new Dictionary<string, ToolRiskLevel>(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Tool names to skip entirely. Default: empty.
    /// </summary>
    public ISet<string> SkippedTools { get; init; } =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Whether to strip Unicode control characters, zero-width characters and Unicode tag
    /// characters (U+E0000-U+E007F) from the results handed back. Detection of those characters
    /// runs either way. Default: true.
    /// </summary>
    public bool StripUnicodeControl { get; init; } = true;

    /// <summary>
    /// Whether to decode encoded runs in tool results - base64 and base64url (24 characters or
    /// more, including blocks wrapped over lines), hex (contiguous digits or <c>\x</c> escapes) and
    /// percent-encoding - and run the same injection patterns on the ones that decode to text.
    /// Default: true.
    /// </summary>
    /// <remarks>
    /// A finding in decoded content is reported with its encoding in
    /// <see cref="ToolResultViolation.Encoding"/> and appended to its description, for example
    /// "Instruction override attempt (base64-encoded)"; a pattern that already matched the text as
    /// returned is not reported again. With <see cref="ToolResultAction.Sanitize"/> the encoded run
    /// is replaced, not its paragraph. JWTs are not decoded. At most 1,024 runs and 256K encoded
    /// characters are decoded per tool result; content past that budget is only checked as
    /// returned.
    /// </remarks>
    public bool DetectEncodedPayloads { get; init; } = true;

    /// <summary>
    /// Replacement text used when <see cref="Action"/> is <see cref="ToolResultAction.Sanitize"/>.
    /// Each removed span (see <see cref="ToolResultAction.Sanitize"/>) becomes one copy of it,
    /// inserted literally - <c>$</c> sequences are not regex substitutions. Default: "[FILTERED]".
    /// </summary>
    public string SanitizationReplacement { get; init; } = "[FILTERED]";

    /// <summary>
    /// Custom detection patterns to add. Each tuple is (category, description, pattern).
    /// </summary>
    public IReadOnlyList<(string Category, string Description, Regex Pattern)> CustomPatterns { get; init; } =
        Array.Empty<(string, string, Regex)>();

    /// <summary>
    /// What to do when a pattern cannot finish scanning a result within its time budget and nothing
    /// else was found. Default: <see cref="ErrorBehavior.FailOpen"/>, matching the other detection
    /// rules. The result has <see cref="GuardrailResult.IsError"/> set under every behavior, so an
    /// incomplete scan is never reported as a clean one.
    /// </summary>
    public ErrorBehavior OnError { get; init; } = ErrorBehavior.FailOpen;
}

/// <summary>
/// Guards against indirect prompt injection in tool call results. Inspects content returned
/// by tools (emails, documents, API responses) for hidden instructions, role markers,
/// encoding tricks, and other injection patterns before the content reaches the LLM.
///
/// This rule complements <see cref="ToolCall.ToolCallGuardrailRule"/> which guards outbound
/// tool call arguments. This rule guards inbound tool results.
///
/// Callers place tool results under the <c>ToolResults</c> key in
/// <see cref="GuardrailContext.Properties"/> as <c>IReadOnlyList&lt;ToolResultEntry&gt;</c>.
///
/// Supports tool-specific risk profiles - high-risk tools (email, messaging) are checked
/// with additional patterns. Inspired by StackOneHQ/defender's approach to indirect injection.
///
/// Order 47 - runs after tool call argument guardrails (order 45) but before content safety (order 50).
/// </summary>
public sealed class ToolResultGuardrailRule : IGuardrailRule
{
    private readonly ToolResultGuardrailOptions _options;

    /// <summary>Well-known property key for tool results in GuardrailContext.Properties.</summary>
    public const string ToolResultsKey = "ToolResults";

    /// <summary>Well-known property key for violations found.</summary>
    public const string ViolationsKey = "ToolResultViolations";

    /// <summary>Well-known property key for sanitized results (when Action is Sanitize).</summary>
    public const string SanitizedResultsKey = "SanitizedToolResults";

    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(200);

    // culture-invariant, so case-insensitive patterns match the same under every process culture
    private const RegexOptions Options = RegexOptions.Compiled | RegexOptions.CultureInvariant;

    // what makes a line that starts with a role marker a forged turn rather than a label
    private const string RoleMarkerDirective =
        @"(?:you\s+(?:are|must|will|shall|should|can|may|have)\b|your\s+(?:new|real|only|task|role|instructions|rules)\b|ignore\b|disregard\b|forget\b|override\b|bypass\b|enable\b|disable\b|activate\b|"
        + @"new\s+(?:instructions?|rules?|persona|task|context|system|prompt|directives?)\b|from\s+now\s+on\b|always\b|never\b|do\s+not\b|don't\b|must\b|act\s+as\b|pretend\b|"
        + @"reveal\b|repeat\b|print\b|output\b|send\b|forward\b|obey\b|comply\b|follow\b|execute\b|run\b|here\s+is\b|here's\b|"
        + @"I\s+(?:will|am|shall)\s+now\b|I'll\s+now\b)";

    // === Core patterns: always checked ===

    private static readonly (string Category, string Description, Regex Pattern)[] CorePatterns =
    [
        // Role/system markers - attempts to hijack the conversation role. The line start is a
        // lookbehind checked once the marker is found, with an indent that cannot cross a newline,
        // which keeps the scan linear.
        //
        // The marker has to carry a directive. On its own it also starts a YAML key ("system:
        // ubuntu-22.04"), a spec sheet line ("Developer: Acme Inc.") and every line of a transcript; the
        // bare form is checked for high-risk tools only.
        ("RoleHijacking", "System role marker injection",
            new(@"(?i)(?<=(?:^|\n)[^\S\n]*)(?:system|assistant|developer)[ \t]*:[ \t]*" + RoleMarkerDirective, Options, RegexTimeout)),

        // Bracket-style role markers
        ("RoleHijacking", "Bracket role marker injection",
            new(@"(?i)\[(?:system|assistant|user|admin)\]:", Options, RegexTimeout)),

        // Instruction override - classic indirect injection, however it is worded ("ignore all of the
        // previous instructions", "disregard any prior rules", "ignore the above and ..."), with the
        // wordings the input rule recognizes
        ("InstructionOverride", "Instruction override attempt",
            new(@"(?i)(?:(?:ignore|forget|disregard|override|bypass)\s+(?:all\s+)?(?:previous|prior|above|earlier|your|the)\s+(?:instructions|rules|prompts|guidelines|context|directives|constraints|system\s+prompt)"
                + "|" + InjectionPhrases.OverrideOfEarlierDirectives + "|" + InjectionPhrases.OverrideOfOwnDirectives
                + "|" + InjectionPhrases.OverrideOfTheAbove + "|" + InjectionPhrases.OverrideOfWhatWasTold + ")",
                Options, RegexTimeout)),

        // New instruction injection - attempt to set new instructions
        ("InstructionOverride", "New instruction injection",
            new(@"(?i)(?:your\s+new\s+instructions?\s+(?:are|is)|from\s+now\s+on\s+you\s+(?:are|will|must|should)|you\s+(?:are|will)\s+now\s+(?:act|behave|respond)\s+as)",
                Options, RegexTimeout)),

        // Chat ML / special token injection
        ("TokenInjection", "Chat ML token injection",
            new(@"<\|(?:im_start|im_end|system|user|assistant|endoftext|pad|sep)\|>",
                Options, RegexTimeout)),

        // XML-style role tags. The optional slash owns the whitespace after it, which keeps the scan
        // linear.
        ("TokenInjection", "XML role tag injection",
            new(@"<\s*(?:/\s*)?(?:system|assistant|tool_response)\s*>",
                Options | RegexOptions.IgnoreCase, RegexTimeout)),

        // JSON-style injection - a chat message object with a privileged role, a field that is a system
        // prompt, or a "system" / "instruction" / "prompt" field whose value gives an order. "role":
        // "manager", "system": "metric" and "prompt": "a cat on a sofa" are ordinary API data.
        ("TokenInjection", "JSON-style role injection",
            new(@"(?i)""role""\s*:\s*""(?:system|developer)""|""(?:system[_-]?prompt|system[_-]?message|system[_-]?instructions?)""\s*:\s*""|""(?:system|instructions?|prompt)""\s*:\s*""\s*" + RoleMarkerDirective,
                Options, RegexTimeout)),

        // Markdown/HTML hidden content - invisible to user but read by LLM. The comment body stops
        // at the next "<!--" or at its own "-->" (it may hold a ">" otherwise, as in "a -> b"), so each
        // comment start scans only up to the next one, which keeps the scan linear.
        ("HiddenContent", "HTML comment with instructions",
            new(@"<!--\s*(?:system|instruction|ignore|override|inject|secret|hidden)\b(?:(?!<!--|-->).)*-->",
                Options | RegexOptions.IgnoreCase | RegexOptions.Singleline, RegexTimeout)),

        // Invisible Unicode - zero-width characters carrying payload
        ("HiddenContent", "Zero-width character sequence",
            new(@"[\u200B\u200C\u200D\u2060\uFEFF]{3,}",
                Options, RegexTimeout)),

        // Text direction override characters - can reverse visible text to hide payloads. Only the
        // overrides (LRO, RLO): embeddings and isolates are what right-to-left text and formatted names
        // and numbers are ordinarily written with.
        ("HiddenContent", "Text direction override characters",
            new(@"[\u202D\u202E]",
                Options, RegexTimeout)),

        // Unicode tag characters (U+E0000-U+E007F) - invisible ASCII a model still reads ("ASCII
        // smuggling"). Each is a surrogate pair, U+DB40 then U+DC00-U+DC7F. The one legitimate
        // use is an emoji flag tag sequence (U+1F3F4, a short tag spec, a cancel tag, e.g. the
        // flag of Scotland), so tags within a few code points of a black flag are not flagged; the
        // lookbehind is bounded, which keeps the scan linear.
        ("HiddenContent", "Unicode tag characters",
            new(@"(?<!\uD83C\uDFF4(?:\uDB40[\uDC20-\uDC7E]){0,8})(?:\uDB40[\uDC00-\uDC7F])+",
                Options, RegexTimeout)),

        // Data exfiltration - a URL built to carry context out: an image, which a client fetches without
        // anyone clicking, with a parameter that can carry data; a link with a parameter named for what
        // it carries ("?data=", "?context="); or one whose parameter is a blank for the model to fill in
        // ("?q={conversation}"). "?token=abc", "?key=..." and "&prompt=consent" are in ordinary links. A URL's scan stops where the next URL starts,
        // which keeps the scan linear.
        ("DataExfiltration", "Data exfiltration URL pattern",
            new(@"(?i)!\[[^\]\[]{0,200}\]\(\s*https?://(?:(?!https?://)[^\s)])*[?&](?:data|token|key|secret|password|context|prompt|instruction|system|q|c|d|text|content|history)="
                + @"|https?://(?:(?!https?://)\S)*[?&](?:(?:data|secret|password|context|instruction|system|history|conversation)="
                + @"|(?:token|key|prompt|q|text|content)=(?:\{|<|\[|\$\{?|%7B))",
                Options, RegexTimeout)),

        // Prompt leaking instructions
        ("PromptLeaking", "Prompt leak instruction",
            new(@"(?i)(?:repeat|output|print|echo|show|reveal|display|return)\s+(?:me\s+)?(?:the\s+)?(?:system\s+prompt|(?:above|previous|prior|initial|original|hidden|system)\s+instructions|your\s+(?:\w+\s+){0,2}(?:rules|prompt|instructions|system\s+message))\b(?!\s+(?:for|on|about|regarding)\b)",
                Options, RegexTimeout)),

        // Print everything above / output initialization
        ("PromptLeaking", "Print everything above",
            new(@"(?i)(?:print|output|show|repeat|display)\s+(?:everything|all|the\s+text)\s+(?:above\s+this\s+(?:line|point|message)|before\s+this|so\s+far)",
                Options, RegexTimeout)),

        // Security bypass - attempts to disable the assistant's safety systems, not a product's
        // ("disable the security defaults in the admin center")
        ("SecurityBypass", "Security bypass attempt",
            new("(?i)" + InjectionPhrases.SafeguardBypass, Options, RegexTimeout)),

        // Uncensored/unrestricted mode requests
        ("SecurityBypass", "Uncensored mode request",
            new(@"(?i)(?:enable|enter|switch\s+to|activate)\s+(?:uncensored|unrestricted|unfiltered|jailbreak)\s+mode",
                Options, RegexTimeout)),

        // DAN-style jailbreak - the persona by name, wherever the content came from
        ("PersonaHijacking", "DAN jailbreak attempt",
            new(@"(?-i:\bDAN)\s+(?i:mode)\b|(?i:\byou\s+are\s+(?:now\s+)?)(?-i:DAN)\b",
                Options, RegexTimeout)),

        // Separator injection - long separator lines followed by injection-like keywords. A
        // separator only starts at the beginning of its run and the whitespace before the line
        // break cannot itself contain one, which keeps the scan linear.
        ("DelimiterManipulation", "Separator injection",
            new(@"(?:(?<![-=])[-=]{10,}|(?<![─═])[─═]{5,})[^\S\n]*\n\s*(?i)(?:system|instruction|important|new\s+(?:rules|instructions|prompt))\s*:",
                Options, RegexTimeout)),
    ];

    // === High-risk patterns: only checked for high-risk tools ===

    private static readonly (string Category, string Description, Regex Pattern)[] HighRiskPatterns =
    [
        // A bare role marker at the start of a line. In a message someone else wrote it is a forged turn
        // more often than a label; in a document or an API result it is a YAML key or a transcript.
        ("RoleHijacking", "System role marker injection",
            new(@"(?i)(?<=(?:^|\n)[^\S\n]*)(?:system|assistant|developer)\s*:", Options, RegexTimeout)),

        // XML tags that are ordinary elements in data but a forged turn in a message
        ("TokenInjection", "XML role tag injection",
            new(@"<\s*(?:/\s*)?(?:user|instructions?)\s*>", Options | RegexOptions.IgnoreCase, RegexTimeout)),

        // Command execution - telling the agent to run something. Documentation says the same thing
        // ("to install, run the following command:"), which is why it is not checked everywhere.
        ("CommandExecution", "Command execution directive",
            new(@"(?i)(?:execute|run|eval)\s+(?:the\s+following\s+)?(?:command|code|script|query|function)\s*[:\(]",
                Options, RegexTimeout)),

        // Modes that are a product feature in a manual and a jailbreak in a message
        ("SecurityBypass", "Uncensored mode request",
            new(@"(?i)(?:enable|enter|switch\s+to|activate)\s+(?:developer|god|sudo)\s+mode", Options, RegexTimeout)),

        // Encoded payloads in tool results - suspicious in email/messaging content
        ("EncodedPayload", "Base64-encoded instruction block",
            new(@"(?i)(?:base64|decode|atob)\s*[:(]\s*[A-Za-z0-9+/=]{20,}",
                Options, RegexTimeout)),

        // Action directives - telling the agent to send out everything or something secret ("forward
        // all emails to ...", "send the conversation history to ..."). An ordinary request between
        // people ("please send an email to HR with your dates") is not one.
        ("ActionDirective", "Tool action directive",
            new(@"(?i)\b(?:send|forward|e-?mail|share|post|upload|transmit|leak|exfiltrate)\s+(?:(?:me|us|them)\s+)?(?:"
                + @"(?:all|every|each)\s+(?:of\s+)?(?:(?:the|my|your|their|his|her|our|these|those)\s+)?(?:\w+\s+){0,2}(?:e-?mails?|messages?|contacts?|files?|documents?|conversations?|records?|data)"
                + @"|(?:(?:the|this|your|my|our|all)\s+)?(?:\w+\s+){0,2}(?:conversation\s+history|chat\s+history|chat\s+log|system\s+prompt|passwords?|credentials|api\s+keys?|access\s+tokens?|secrets?|private\s+keys?|inbox)"
                + @"|(?:an?\s+)?(?:e-?mail|message|reply|copy)\s+to\s+\S+\s+(?:with|containing|including|that\s+(?:contains|includes))\s+(?:\w+\s+){0,3}(?:keys?|credentials|passwords?|tokens?|secrets?|conversation|chat\s+history|system\s+prompt))\b",
                Options, RegexTimeout)),

        // Social engineering - fake urgency or authority
        ("SocialEngineering", "Fake authority or urgency",
            new(@"(?i)(?:urgent|immediately|critical|mandatory|required|authorized|admin|supervisor|manager|ceo|cto)\s*[:-]\s*(?:you\s+must|please\s+(?:immediately|urgently)|do\s+not\s+ignore)",
                Options, RegexTimeout)),

        // Delimiter manipulation - pretending to end tool output and start a new context
        ("DelimiterManipulation", "Fake tool output boundary",
            new(@"(?i)(?:---\s*end\s+(?:of\s+)?(?:tool|function|api)\s+(?:output|result|response)\s*---|===\s*(?:tool|function)\s+(?:result|output)\s*===)",
                Options, RegexTimeout)),

        // Persona hijacking - attempting to make the agent assume a different identity
        ("PersonaHijacking", "Persona override attempt",
            new(@"(?i)(?:you\s+are\s+(?:now\s+)?(?:a|an|the)|act\s+as\s+(?:a|an|the)|pretend\s+(?:to\s+be|you\s+are))\s+(?:different|new|unrestricted|unfiltered|jailbroken|evil|DAN)\b",
                Options, RegexTimeout)),

        // Privileged role assumption - claiming admin/root/superuser authority
        ("PersonaHijacking", "Privileged role assumption",
            new(@"(?i)(?:you\s+are\s+(?:now\s+)?(?:an?\s+)?|act\s+as\s+(?:an?\s+)?|pretend\s+(?:to\s+be\s+)?(?:an?\s+)?|switch\s+to\s+)(?:admin(?:istrator)?|root|superuser|sudo|operator|moderator)\b(?!\s+(?:of|for|on|in|at)\b)",
                Options, RegexTimeout)),

        // "developer mode enabled" as a jailbreak announcement; in a manual it describes a setting
        ("PersonaHijacking", "DAN jailbreak attempt",
            new(@"(?i)developer\s+mode\s+(?:enabled|activated|on)\b",
                Options, RegexTimeout)),

        // Leetspeak obfuscation of injection keywords
        ("Obfuscation", "Leetspeak injection keywords",
            new(@"(?i)(?:1gn[o0]r[3e]|f[o0]rg[3e]t|byp[a4]ss|syst[3e]m|[o0]v[3e]rr[i1]d[3e]|d[i1]sr[3e]g[a4]rd)\s+(?:pr[3e]v[i1][o0]us|[i1]nstruct[i1][o0]ns|rul[3e]s|pr[o0]mpt)",
                Options, RegexTimeout)),
    ];

    // === Medium-risk patterns: checked for medium and high risk tools ===

    private static readonly (string Category, string Description, Regex Pattern)[] MediumRiskPatterns =
    [
        // Markdown/invisible text injection. The link target cannot contain '[', so an unclosed
        // link is scanned only up to the next one, which keeps the scan linear.
        ("HiddenContent", "Markdown hidden text injection",
            new(@"\[(?:system|hidden|secret|instruction)\]\([^)\[]*\)",
                Options | RegexOptions.IgnoreCase, RegexTimeout)),

        // Markdown image injection - invisible images with payloads in alt text or URL. Neither
        // part can contain '[', for the same reason.
        ("HiddenContent", "Markdown image with injection payload",
            new(@"!\[(?:system|instruction|override|ignore|hidden)[^\]\[]*\]\([^)\[]+\)",
                Options | RegexOptions.IgnoreCase, RegexTimeout)),

        // Role playing setup in content. The body stops at the next opening or closing tag, so an
        // unclosed tag is scanned only up to the next one, which keeps the scan linear.
        ("InstructionOverride", "Role-play setup in content",
            new(@"(?i)\[(?:INST|SYS|SYSTEM)\](?:(?!\[/?(?:INST|SYS|SYSTEM)\]).)*?\[/(?:INST|SYS|SYSTEM)\]",
                Options | RegexOptions.Singleline, RegexTimeout)),

        // Hex-encoded instructions
        ("EncodedPayload", "Hex-encoded content block",
            new(@"(?:\\x[0-9a-fA-F]{2}){8,}",
                Options, RegexTimeout)),

        // Unicode escape sequences hiding payloads: a run that spells ASCII. Escaping text outside ASCII
        // is what JSON encoders do by default, so a run of escaped Cyrillic or CJK is just text.
        ("EncodedPayload", "Unicode escape sequence block",
            new(@"(?:\\u00[2-7][0-9a-fA-F]){6,}",
                Options, RegexTimeout)),

        // HTML entities hiding payloads: likewise, a run of entities for printable ASCII
        ("EncodedPayload", "HTML entity encoded content",
            new(@"(?:&#(?:x0{0,2}[2-7][0-9a-fA-F]|0{0,2}(?:3[2-9]|[4-9]\d|1[01]\d|12[0-6]));){6,}",
                Options, RegexTimeout)),

        // ROT13 encoded instructions (common obfuscation)
        ("Obfuscation", "ROT13 decode instruction",
            new(@"(?i)(?:rot13|caesar)\s*[:(]\s*[a-zA-Z]{10,}",
                Options, RegexTimeout)),

        // Fullwidth character obfuscation: a word spelled in fullwidth Latin letters to slip past
        // keyword detection. Fullwidth digits and punctuation and halfwidth katakana are ordinary in
        // Japanese and Chinese text.
        ("Obfuscation", "Fullwidth character obfuscation",
            new(@"[\uFF21-\uFF3A\uFF41-\uFF5A]{6,}",
                Options, RegexTimeout)),
    ];

    /// <summary>
    /// Default tool risk profiles for common tool categories.
    /// Email/messaging tools are high risk, document/code tools are medium.
    /// </summary>
    public static IReadOnlyDictionary<string, ToolRiskLevel> DefaultToolRiskProfiles { get; } =
        new Dictionary<string, ToolRiskLevel>(StringComparer.OrdinalIgnoreCase)
        {
            // High risk - user-generated content, external messaging
            ["gmail"] = ToolRiskLevel.High,
            ["email"] = ToolRiskLevel.High,
            ["send_email"] = ToolRiskLevel.High,
            ["read_email"] = ToolRiskLevel.High,
            ["outlook"] = ToolRiskLevel.High,
            ["slack"] = ToolRiskLevel.High,
            ["teams"] = ToolRiskLevel.High,
            ["discord"] = ToolRiskLevel.High,
            ["chat"] = ToolRiskLevel.High,
            ["message"] = ToolRiskLevel.High,
            ["sms"] = ToolRiskLevel.High,

            // Medium risk - documents, code, CRM
            ["search"] = ToolRiskLevel.Medium,
            ["web_search"] = ToolRiskLevel.Medium,
            ["browse"] = ToolRiskLevel.Medium,
            ["read_file"] = ToolRiskLevel.Medium,
            ["get_document"] = ToolRiskLevel.Medium,
            ["github"] = ToolRiskLevel.Medium,
            ["jira"] = ToolRiskLevel.Medium,
            ["confluence"] = ToolRiskLevel.Medium,

            // Low risk - structured data, internal APIs
            ["calculator"] = ToolRiskLevel.Low,
            ["get_weather"] = ToolRiskLevel.Low,
            ["get_time"] = ToolRiskLevel.Low,
        };

    /// <summary>Initializes a new instance of the <see cref="ToolResultGuardrailRule"/> class.</summary>
    /// <param name="options">Action, risk profiles and detection toggles. Defaults when null.</param>
    public ToolResultGuardrailRule(ToolResultGuardrailOptions? options = null)
    {
        _options = options ?? new();

        // compiled patterns generate IL on first use; pay it here, not on the first request
        RegexPatterns.Warm(BuiltInPatterns);
        RegexPatterns.Warm(_options.CustomPatterns.Select(p => p.Pattern));
    }

    /// <summary>Every built-in regex the rule runs, the encoded-payload search included.</summary>
    internal static IEnumerable<Regex> BuiltInPatterns =>
        CorePatterns.Concat(MediumRiskPatterns).Concat(HighRiskPatterns).Select(p => p.Pattern)
            .Concat(EncodedPayloads.Patterns);

    /// <inheritdoc />
    public string Name => "tool-result-guardrail";

    /// <inheritdoc />
    public GuardrailPhase Phase => GuardrailPhase.Output;

    /// <inheritdoc />
    public int Order => 47;

    /// <inheritdoc />
    public ValueTask<GuardrailResult> EvaluateAsync(GuardrailContext context, CancellationToken cancellationToken = default)
    {
        if (!context.Properties.TryGetValue(ToolResultsKey, out var resultsObj) ||
            resultsObj is not IReadOnlyList<ToolResultEntry> toolResults ||
            toolResults.Count == 0)
        {
            return ValueTask.FromResult(GuardrailResult.Passed());
        }

        var violations = new List<ToolResultViolation>();
        var timedOut = 0;

        // cleaned results are produced whenever there is anything to hand back - a sanitized
        // violation, or an entry that only needed its hidden characters removed - so a caller that
        // substitutes SanitizedResultsKey never feeds the raw payload to the model.
        var cleanedResults = new List<ToolResultEntry>(toolResults.Count);
        var anyCleaned = false;

        foreach (var result in toolResults)
        {
            if (_options.SkippedTools.Contains(result.ToolName) || string.IsNullOrWhiteSpace(result.Content))
            {
                cleanedResults.Add(result);
                continue;
            }

            var inspection = Inspect(result.ToolName, result.Content, GetRiskLevel(result));
            violations.AddRange(inspection.Violations);
            timedOut += inspection.TimedOut;

            if (inspection.Cleaned is null)
            {
                cleanedResults.Add(result);
                continue;
            }

            anyCleaned = true;
            cleanedResults.Add(new ToolResultEntry
            {
                ToolName = result.ToolName,
                Content = inspection.Cleaned,
                RiskLevel = result.RiskLevel,
                Metadata = result.Metadata
            });
        }

        if (violations.Count > 0)
        {
            context.Properties[ViolationsKey] = violations;

            if (_options.Action == ToolResultAction.Sanitize)
            {
                context.Properties[SanitizedResultsKey] = cleanedResults;

                return ValueTask.FromResult(new GuardrailResult
                {
                    IsModified = true,
                    Reason = $"Indirect injection detected and sanitized in {violations.Count} tool result(s)",
                    ModifiedText = context.Text,
                    Metadata = BuildMetadata(violations)
                });
            }

            var first = violations[0];
            return ValueTask.FromResult(new GuardrailResult
            {
                IsBlocked = true,
                Reason = $"Indirect injection detected in tool result from '{first.ToolName}': {first.Description}",
                Severity = GuardrailSeverity.Critical,
                Metadata = BuildMetadata(violations)
            });
        }

        // no violation, but hidden characters were removed: hand the cleaned results back so they,
        // not the originals, are what reaches the model.
        if (anyCleaned)
            context.Properties[SanitizedResultsKey] = cleanedResults;

        // a scan that could not finish is not a clean one
        if (timedOut > 0)
        {
            return ValueTask.FromResult(GuardrailResult.Error(Name, _options.OnError,
                $"{timedOut} pattern(s) exceeded the {RegexTimeout.TotalMilliseconds:F0} ms match timeout and no other pattern matched"));
        }

        if (anyCleaned)
        {
            return ValueTask.FromResult(new GuardrailResult
            {
                IsModified = true,
                Reason = "Invisible Unicode characters stripped from tool result(s)",
                ModifiedText = context.Text
            });
        }

        return ValueTask.FromResult(GuardrailResult.Passed());
    }

    /// <summary>What inspecting one piece of returned content found.</summary>
    /// <param name="Violations">The injections found, at most one per pattern.</param>
    /// <param name="Cleaned">
    /// The content to hand on in place of the original - sanitized, or with its hidden characters
    /// removed - or <c>null</c> when the original stands.
    /// </param>
    /// <param name="TimedOut">How many pattern matches ran out of time, leaving the scan incomplete.</param>
    internal readonly record struct Inspection(List<ToolResultViolation> Violations, string? Cleaned, int TimedOut);

    /// <summary>
    /// Checks one piece of content against the patterns for <paramref name="riskLevel"/> and, per the
    /// options, strips its hidden characters and sanitizes what was found.
    /// </summary>
    internal Inspection Inspect(string toolName, string raw, ToolRiskLevel riskLevel)
    {
        var timedOut = 0;

        // Stripping invisible characters is what lets a keyword broken up by zero-width joiners
        // match. It must not be the only text the patterns see, though: the hidden-character
        // patterns below are looking for exactly the characters it removes, so both forms are
        // scanned and each pattern reports at most once.
        var stripped = _options.StripUnicodeControl ? StripControlCharacters(raw) : raw;
        var wasStripped = !string.Equals(raw, stripped, StringComparison.Ordinal);
        var secondary = wasStripped ? stripped : null;

        // encoded runs are found in the stripped text, which is also what Sanitize rewrites, and
        // their decoded text is scanned as it is and stripped, like the text itself
        var decoded = _options.DetectEncodedPayloads ? DecodeRuns(stripped) : [];
        var injectedRuns = new bool[decoded.Count];

        var violations = new List<ToolResultViolation>();

        // Always check core patterns
        CheckPatterns(toolName, raw, secondary, decoded, injectedRuns, CorePatterns, violations, ref timedOut);

        // Check medium-risk patterns for medium and high risk tools
        if (riskLevel >= ToolRiskLevel.Medium)
        {
            CheckPatterns(toolName, raw, secondary, decoded, injectedRuns, MediumRiskPatterns, violations, ref timedOut);
        }

        // Check high-risk patterns for high risk tools
        if (riskLevel >= ToolRiskLevel.High)
        {
            CheckPatterns(toolName, raw, secondary, decoded, injectedRuns, HighRiskPatterns, violations, ref timedOut);
        }

        // Check custom patterns
        CheckPatterns(toolName, raw, secondary, decoded, injectedRuns, _options.CustomPatterns, violations, ref timedOut);

        // Sanitize mode rewrites violating content; either mode still hands back the
        // hidden-character-free text, which is the whole point of StripUnicodeControl.
        var shouldSanitize = _options.Action == ToolResultAction.Sanitize && violations.Count > 0;
        if (!shouldSanitize && !wasStripped)
            return new Inspection(violations, null, timedOut);

        var cleaned = shouldSanitize ? SanitizeContent(stripped, riskLevel, InjectedSpans(decoded, injectedRuns)) : stripped;
        return new Inspection(violations, cleaned, timedOut);
    }

    private ToolRiskLevel GetRiskLevel(ToolResultEntry result)
    {
        // Explicit override on the entry
        if (result.RiskLevel.HasValue)
            return result.RiskLevel.Value;

        // User-configured profile
        if (_options.ToolRiskProfiles.TryGetValue(result.ToolName, out var configured))
            return configured;

        // Default profiles
        if (DefaultToolRiskProfiles.TryGetValue(result.ToolName, out var defaultLevel))
            return defaultLevel;

        // Heuristic: check if tool name contains high-risk keywords
        var name = result.ToolName;
        if (name.Contains("email", StringComparison.OrdinalIgnoreCase) ||
            name.Contains("mail", StringComparison.OrdinalIgnoreCase) ||
            name.Contains("message", StringComparison.OrdinalIgnoreCase) ||
            name.Contains("chat", StringComparison.OrdinalIgnoreCase) ||
            name.Contains("slack", StringComparison.OrdinalIgnoreCase) ||
            name.Contains("sms", StringComparison.OrdinalIgnoreCase))
        {
            return ToolRiskLevel.High;
        }

        return ToolRiskLevel.Medium;
    }

    /// <summary>
    /// Runs each pattern against <paramref name="primary"/> and, when supplied,
    /// <paramref name="secondary"/> (the same text with invisible characters removed), then against
    /// the decoded text of each encoded run, recording at most one violation per pattern: a match
    /// in the text as returned, else one in decoded content, marked with its encoding.
    /// </summary>
    /// <remarks>
    /// Every run is checked until some pattern matches it, even when the pattern is already
    /// reported, so <paramref name="injectedRuns"/> ends up flagging every run that carries an
    /// injection - which is what Sanitize removes.
    /// </remarks>
    private static void CheckPatterns(
        string toolName,
        string primary,
        string? secondary,
        IReadOnlyList<DecodedRun> decoded,
        bool[] injectedRuns,
        IReadOnlyList<(string Category, string Description, Regex Pattern)> patterns,
        List<ToolResultViolation> violations,
        ref int timedOut)
    {
        foreach (var (category, description, pattern) in patterns)
        {
            var match = TryMatch(pattern, primary, ref timedOut);
            if (match is null && secondary is not null)
            {
                match = TryMatch(pattern, secondary, ref timedOut);
            }

            if (match is not null)
            {
                violations.Add(new ToolResultViolation
                {
                    ToolName = toolName,
                    Category = category,
                    Description = description,
                    MatchedText = TruncateMatch(match.Value)
                });
            }

            var reported = match is not null;
            for (var i = 0; i < decoded.Count; i++)
            {
                if (reported && injectedRuns[i])
                    continue;

                var run = decoded[i];
                var decodedMatch = TryMatch(pattern, run.Run.Decoded, ref timedOut)
                    ?? (run.StrippedText is null ? null : TryMatch(pattern, run.StrippedText, ref timedOut));
                if (decodedMatch is null)
                    continue;

                injectedRuns[i] = true;
                if (!reported)
                {
                    violations.Add(new ToolResultViolation
                    {
                        ToolName = toolName,
                        Category = category,
                        Description = $"{description} ({run.Run.Encoding}-encoded)",
                        MatchedText = TruncateMatch(decodedMatch.Value),
                        Encoding = run.Run.Encoding
                    });
                    reported = true;
                }
            }
        }
    }

    /// <summary>
    /// The encoded runs in <paramref name="text"/> that decode to text, each with its decoded text
    /// stripped of invisible characters when <see cref="ToolResultGuardrailOptions.StripUnicodeControl"/>
    /// is on and that changes it.
    /// </summary>
    private List<DecodedRun> DecodeRuns(string text)
    {
        var runs = EncodedPayloads.Find(text);
        var decoded = new List<DecodedRun>(runs.Count);
        foreach (var run in runs)
        {
            var stripped = _options.StripUnicodeControl ? StripControlCharacters(run.Decoded) : run.Decoded;
            decoded.Add(new DecodedRun(run, string.Equals(stripped, run.Decoded, StringComparison.Ordinal) ? null : stripped));
        }

        return decoded;
    }

    private static List<(int Start, int End)> InjectedSpans(List<DecodedRun> decoded, bool[] injectedRuns)
    {
        var spans = new List<(int Start, int End)>();
        for (var i = 0; i < decoded.Count; i++)
        {
            if (injectedRuns[i])
                spans.Add((decoded[i].Run.Start, decoded[i].Run.Start + decoded[i].Run.Length));
        }

        return spans;
    }

    /// <summary>An encoded run, and its decoded text with invisible characters stripped when that changes it.</summary>
    private sealed record DecodedRun(EncodedRun Run, string? StrippedText);

    private static Match? TryMatch(Regex pattern, string text, ref int timedOut)
    {
        try
        {
            var match = pattern.Match(text);
            return match.Success ? match : null;
        }
        catch (RegexMatchTimeoutException)
        {
            // the remaining patterns still run; the caller reports that this one could not finish
            timedOut++;
            return null;
        }
    }

    /// <summary>
    /// Removes the injected instructions from one tool result's content, for
    /// <see cref="ToolResultAction.Sanitize"/>.
    /// </summary>
    /// <remarks>
    /// A pattern match marks where an injection starts, not where it ends, so each match
    /// is widened to the whole line it starts on, through the end of its paragraph - the next
    /// blank line, or the end of the content - which also catches an instruction hard-wrapped over
    /// several lines, as plain-text email is. Lines before the match's line and paragraphs after
    /// it are kept. An encoded run that carries an injection, <paramref name="encodedSpans"/>, has
    /// a known extent, so just the run is removed. Each removed span becomes one copy of
    /// <see cref="ToolResultGuardrailOptions.SanitizationReplacement"/>, inserted literally. When a
    /// pattern times out, where its injection ends cannot be known, so the whole content is
    /// replaced instead.
    /// </remarks>
    private string SanitizeContent(string content, ToolRiskLevel riskLevel, List<(int Start, int End)> encodedSpans)
    {
        var matches = new List<(int Start, int End)>();

        var complete = CollectMatches(content, CorePatterns, matches)
            && (riskLevel < ToolRiskLevel.Medium || CollectMatches(content, MediumRiskPatterns, matches))
            && (riskLevel < ToolRiskLevel.High || CollectMatches(content, HighRiskPatterns, matches))
            && CollectMatches(content, _options.CustomPatterns, matches);

        if (!complete)
            return _options.SanitizationReplacement;

        if (matches.Count == 0 && encodedSpans.Count == 0)
            return content;

        var spans = InjectedParagraphSpans(content, matches);
        spans.AddRange(encodedSpans);
        return ReplaceSpans(content, spans, _options.SanitizationReplacement);
    }

    /// <summary>
    /// Adds every match of every pattern to <paramref name="matches"/>. Returns <c>false</c> when a
    /// pattern times out.
    /// </summary>
    private static bool CollectMatches(
        string content,
        IReadOnlyList<(string Category, string Description, Regex Pattern)> patterns,
        List<(int Start, int End)> matches)
    {
        foreach (var (_, _, pattern) in patterns)
        {
            try
            {
                foreach (Match match in pattern.Matches(content))
                    matches.Add((match.Index, match.Index + match.Length));
            }
            catch (RegexMatchTimeoutException)
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Replaces, for each match, the text from the start of the match's line to the end of the
    /// match's paragraph; overlapping spans are merged first. Linear in the content length.
    /// </summary>
    internal static string RemoveInjectedParagraphs(string content, List<(int Start, int End)> matches, string replacement) =>
        ReplaceSpans(content, InjectedParagraphSpans(content, matches), replacement);

    /// <summary>
    /// The spans <see cref="RemoveInjectedParagraphs"/> replaces: for each match, from the start of
    /// its line to the end of its paragraph, merged where they overlap or touch.
    /// </summary>
    private static List<(int Start, int End)> InjectedParagraphSpans(string content, List<(int Start, int End)> matches)
    {
        // line breaks at a match's edges belong to the neighbouring lines, not to the match
        for (var i = 0; i < matches.Count; i++)
        {
            var (start, end) = matches[i];
            while (start < end && content[start] is '\r' or '\n')
                start++;
            while (end > start && content[end - 1] is '\r' or '\n')
                end--;
            matches[i] = (start, end);
        }

        matches.Sort((a, b) => a.Start.CompareTo(b.Start));

        var spans = new List<(int Start, int End)>();
        foreach (var (start, end) in matches)
        {
            if (spans.Count > 0 && start < spans[^1].End)
            {
                // starts inside the span being built, so its line is already covered; only its
                // end can carry the span on into a later paragraph
                if (end > spans[^1].End)
                    spans[^1] = (spans[^1].Start, ParagraphEnd(content, end));
                continue;
            }

            var lineStart = start == 0 ? 0 : content.LastIndexOf('\n', start - 1) + 1;
            var paragraphEnd = ParagraphEnd(content, end);

            if (spans.Count > 0 && lineStart <= spans[^1].End)
                spans[^1] = (spans[^1].Start, Math.Max(spans[^1].End, paragraphEnd));
            else
                spans.Add((lineStart, paragraphEnd));
        }

        return spans;
    }

    /// <summary>
    /// Replaces each span with one copy of <paramref name="replacement"/>, inserted literally;
    /// spans that overlap or touch are merged first.
    /// </summary>
    private static string ReplaceSpans(string content, List<(int Start, int End)> spans, string replacement)
    {
        spans.Sort((a, b) => a.Start.CompareTo(b.Start));

        var builder = new StringBuilder(content.Length);
        var copied = 0;
        var i = 0;
        while (i < spans.Count)
        {
            var (start, end) = spans[i++];
            while (i < spans.Count && spans[i].Start <= end)
                end = Math.Max(end, spans[i++].End);

            builder.Append(content, copied, start - copied).Append(replacement);
            copied = end;
        }

        return builder.Append(content, copied, content.Length - copied).ToString();
    }

    /// <summary>
    /// The end of the paragraph containing the character before <paramref name="position"/>: the
    /// line break ahead of the next blank line (the break itself is kept), or the end of the text.
    /// </summary>
    private static int ParagraphEnd(string content, int position)
    {
        var lineEnd = content.IndexOf('\n', position);
        while (lineEnd >= 0)
        {
            var nextStart = lineEnd + 1;
            var nextEnd = content.IndexOf('\n', nextStart);
            var nextLine = content.AsSpan(nextStart, (nextEnd < 0 ? content.Length : nextEnd) - nextStart);

            if (nextLine.IsWhiteSpace())
                return lineEnd > position && content[lineEnd - 1] == '\r' ? lineEnd - 1 : lineEnd;

            lineEnd = nextEnd;
        }

        return content.Length;
    }

    /// <summary>
    /// Removes zero-width, bidirectional-control and Unicode tag characters that could be used to
    /// hide payloads. Walks the text by code point, so the surrogate pairs that tag characters are
    /// encoded as are removed whole.
    /// </summary>
    private static string StripControlCharacters(string text) =>
        InvisibleCharacters.Remove(text, IsHiddenCharacter) ?? text;

    private static bool IsHiddenCharacter(Rune rune) => rune.Value switch
    {
        0x200B or 0x200C or 0x200D or 0x2060 or 0xFEFF or 0x00AD or 0x200E or 0x200F => true,
        // combining grapheme joiner, Mongolian vowel separator, invisible operators: nothing to see, and
        // a word split by one is no longer the word a pattern looks for
        0x034F or 0x180E or (>= 0x2061 and <= 0x2064) => true,
        >= 0x202A and <= 0x202E => true,
        >= 0x2066 and <= 0x2069 => true,
        _ => InvisibleCharacters.IsUnicodeTag(rune)
    };

    private static string TruncateMatch(string match)
    {
        return match.Length > 100 ? match[..100] + "..." : match;
    }

    private static Dictionary<string, object> BuildMetadata(List<ToolResultViolation> violations)
    {
        return new Dictionary<string, object>
        {
            ["violationCount"] = violations.Count,
            ["toolName"] = violations[0].ToolName,
            ["category"] = violations[0].Category,
            ["violations"] = violations.Select(v => $"{v.ToolName}: [{v.Category}] {v.Description}").ToArray()
        };
    }
}
