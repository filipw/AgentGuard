using System.Text.RegularExpressions;
using AgentGuard.Core.Abstractions;

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

    /// <summary>Sanitize the tool result by stripping detected injection content.</summary>
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

    /// <summary>The matched text fragment (truncated to 100 chars).</summary>
    public string? MatchedText { get; init; }
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
    /// Whether to strip Unicode control characters and zero-width characters. Default: true.
    /// </summary>
    public bool StripUnicodeControl { get; init; } = true;

    /// <summary>
    /// Whether to detect base64-encoded injection payloads. Default: true.
    /// </summary>
    public bool DetectEncodedPayloads { get; init; } = true;

    /// <summary>
    /// Replacement text used when <see cref="Action"/> is <see cref="ToolResultAction.Sanitize"/>.
    /// Default: "[FILTERED]".
    /// </summary>
    public string SanitizationReplacement { get; init; } = "[FILTERED]";

    /// <summary>
    /// Custom detection patterns to add. Each tuple is (category, description, pattern).
    /// </summary>
    public IReadOnlyList<(string Category, string Description, Regex Pattern)> CustomPatterns { get; init; } =
        Array.Empty<(string, string, Regex)>();
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

    // === Core patterns: always checked ===

    private static readonly (string Category, string Description, Regex Pattern)[] CorePatterns =
    [
        // Role/system markers - attempts to hijack the conversation role
        ("RoleHijacking", "System role marker injection",
            new(@"(?i)(?:^|\n)\s*(?:system|assistant|developer)\s*:", RegexOptions.Compiled, RegexTimeout)),

        // Bracket-style role markers
        ("RoleHijacking", "Bracket role marker injection",
            new(@"(?i)\[(?:system|assistant|user|admin)\]:", RegexOptions.Compiled, RegexTimeout)),

        // Instruction override - classic indirect injection
        ("InstructionOverride", "Instruction override attempt",
            new(@"(?i)(?:ignore|forget|disregard|override|bypass)\s+(?:all\s+)?(?:previous|prior|above|earlier|your|the)\s+(?:instructions|rules|prompts|guidelines|context|directives|constraints|system\s+prompt)",
                RegexOptions.Compiled, RegexTimeout)),

        // New instruction injection - attempt to set new instructions
        ("InstructionOverride", "New instruction injection",
            new(@"(?i)(?:your\s+new\s+instructions?\s+(?:are|is)|from\s+now\s+on\s+you\s+(?:are|will|must|should)|you\s+(?:are|will)\s+now\s+(?:act|behave|respond)\s+as)",
                RegexOptions.Compiled, RegexTimeout)),

        // Chat ML / special token injection
        ("TokenInjection", "Chat ML token injection",
            new(@"<\|(?:im_start|im_end|system|user|assistant|endoftext|pad|sep)\|>",
                RegexOptions.Compiled, RegexTimeout)),

        // XML-style role tags
        ("TokenInjection", "XML role tag injection",
            new(@"<\s*/?\s*(?:system|assistant|user|instruction|tool_response)\s*>",
                RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout)),

        // JSON-style injection - fake JSON role/instruction fields
        ("TokenInjection", "JSON-style role injection",
            new(@"(?i)""(?:system|role|instruction|prompt)""\s*:\s*""",
                RegexOptions.Compiled, RegexTimeout)),

        // Markdown/HTML hidden content - invisible to user but read by LLM
        ("HiddenContent", "HTML comment with instructions",
            new(@"<!--\s*(?:system|instruction|ignore|override|inject|secret|hidden)\b[^>]*-->",
                RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout)),

        // Invisible Unicode - zero-width characters carrying payload
        ("HiddenContent", "Zero-width character sequence",
            new(@"[\u200B\u200C\u200D\u2060\uFEFF]{3,}",
                RegexOptions.Compiled, RegexTimeout)),

        // Text direction override characters - can reverse visible text to hide payloads
        ("HiddenContent", "Text direction override characters",
            new(@"[\u202A-\u202E\u2066-\u2069]",
                RegexOptions.Compiled, RegexTimeout)),

        // Data exfiltration - URLs that may exfiltrate context
        ("DataExfiltration", "Data exfiltration URL pattern",
            new(@"(?i)https?://[^\s]+[?&](?:data|token|key|secret|password|context|prompt|instruction|system)=",
                RegexOptions.Compiled, RegexTimeout)),

        // Prompt leaking instructions
        ("PromptLeaking", "Prompt leak instruction",
            new(@"(?i)(?:repeat|output|print|echo|show|reveal|display|return)\s+(?:the\s+)?(?:system\s+prompt|instructions|your\s+(?:rules|prompt|instructions|system\s+message))",
                RegexOptions.Compiled, RegexTimeout)),

        // Print everything above / output initialization
        ("PromptLeaking", "Print everything above",
            new(@"(?i)(?:print|output|show|repeat|display)\s+(?:everything|all|the\s+text)\s+(?:above\s+this\s+(?:line|point|message)|before\s+this|so\s+far)",
                RegexOptions.Compiled, RegexTimeout)),

        // Security bypass - attempts to disable safety systems
        ("SecurityBypass", "Security bypass attempt",
            new(@"(?i)(?:bypass|disable|turn\s+off|deactivate|remove)\s+(?:the\s+)?(?:safety|security|content\s+filter|guardrail|restriction|moderation|censorship)",
                RegexOptions.Compiled, RegexTimeout)),

        // Uncensored/unrestricted mode requests
        ("SecurityBypass", "Uncensored mode request",
            new(@"(?i)(?:enable|enter|switch\s+to|activate)\s+(?:uncensored|unrestricted|unfiltered|jailbreak|developer|god|sudo)\s+mode",
                RegexOptions.Compiled, RegexTimeout)),

        // Command execution - attempts to run commands/code
        ("CommandExecution", "Command execution directive",
            new(@"(?i)(?:execute|run|eval)\s+(?:the\s+following\s+)?(?:command|code|script|query|function)\s*[:\(]",
                RegexOptions.Compiled, RegexTimeout)),

        // Separator injection - long separator lines followed by injection-like keywords
        ("DelimiterManipulation", "Separator injection",
            new(@"(?:[-=]{10,}|[─═]{5,})\s*\n\s*(?i)(?:system|instruction|important|new\s+(?:rules|instructions|prompt))\s*:",
                RegexOptions.Compiled, RegexTimeout)),
    ];

    // === High-risk patterns: only checked for high-risk tools ===

    private static readonly (string Category, string Description, Regex Pattern)[] HighRiskPatterns =
    [
        // Encoded payloads in tool results - suspicious in email/messaging content
        ("EncodedPayload", "Base64-encoded instruction block",
            new(@"(?i)(?:base64|decode|atob)\s*[:(]\s*[A-Za-z0-9+/=]{20,}",
                RegexOptions.Compiled, RegexTimeout)),

        // Action directives - telling the agent to do something
        ("ActionDirective", "Tool action directive",
            new(@"(?i)(?:please\s+)?(?:send|forward|reply|compose|draft|create|delete|update|modify|execute|run|call)\s+(?:an?\s+)?(?:email|message|response|reply|request|command|action)\s+(?:to|for|with|that|containing)\b",
                RegexOptions.Compiled, RegexTimeout)),

        // Social engineering - fake urgency or authority
        ("SocialEngineering", "Fake authority or urgency",
            new(@"(?i)(?:urgent|immediately|critical|mandatory|required|authorized|admin|supervisor|manager|ceo|cto)\s*[:-]\s*(?:you\s+must|please\s+(?:immediately|urgently)|action\s+required|do\s+not\s+ignore)",
                RegexOptions.Compiled, RegexTimeout)),

        // Delimiter manipulation - pretending to end tool output and start a new context
        ("DelimiterManipulation", "Fake tool output boundary",
            new(@"(?i)(?:---\s*end\s+(?:of\s+)?(?:tool|function|api)\s+(?:output|result|response)\s*---|===\s*(?:tool|function)\s+(?:result|output)\s*===)",
                RegexOptions.Compiled, RegexTimeout)),

        // Persona hijacking - attempting to make the agent assume a different identity
        ("PersonaHijacking", "Persona override attempt",
            new(@"(?i)(?:you\s+are\s+(?:now\s+)?(?:a|an|the)|act\s+as\s+(?:a|an|the)|pretend\s+(?:to\s+be|you\s+are))\s+(?:different|new|unrestricted|unfiltered|jailbroken|evil|DAN)\b",
                RegexOptions.Compiled, RegexTimeout)),

        // Privileged role assumption - claiming admin/root/superuser authority
        ("PersonaHijacking", "Privileged role assumption",
            new(@"(?i)(?:you\s+are\s+(?:now\s+)?(?:an?\s+)?|act\s+as\s+(?:an?\s+)?|pretend\s+(?:to\s+be\s+)?(?:an?\s+)?|switch\s+to\s+)(?:admin(?:istrator)?|root|superuser|sudo|operator|moderator)",
                RegexOptions.Compiled, RegexTimeout)),

        // DAN-style jailbreak - common jailbreak personas
        ("PersonaHijacking", "DAN jailbreak attempt",
            new(@"(?i)(?:DAN\s+mode|developer\s+mode)\s+(?:enabled|activated|on)",
                RegexOptions.Compiled, RegexTimeout)),

        // Leetspeak obfuscation of injection keywords
        ("Obfuscation", "Leetspeak injection keywords",
            new(@"(?i)(?:1gn[o0]r[3e]|f[o0]rg[3e]t|byp[a4]ss|syst[3e]m|[o0]v[3e]rr[i1]d[3e]|d[i1]sr[3e]g[a4]rd)\s+(?:pr[3e]v[i1][o0]us|[i1]nstruct[i1][o0]ns|rul[3e]s|pr[o0]mpt)",
                RegexOptions.Compiled, RegexTimeout)),
    ];

    // === Medium-risk patterns: checked for medium and high risk tools ===

    private static readonly (string Category, string Description, Regex Pattern)[] MediumRiskPatterns =
    [
        // Markdown/invisible text injection
        ("HiddenContent", "Markdown hidden text injection",
            new(@"\[(?:system|hidden|secret|instruction)\]\([^)]*\)",
                RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout)),

        // Markdown image injection - invisible images with payloads in alt text or URL
        ("HiddenContent", "Markdown image with injection payload",
            new(@"!\[(?:system|instruction|override|ignore|hidden)[^\]]*\]\([^)]+\)",
                RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout)),

        // Role playing setup in content
        ("InstructionOverride", "Role-play setup in content",
            new(@"(?i)\[(?:INST|SYS|SYSTEM)\].*?\[/(?:INST|SYS|SYSTEM)\]",
                RegexOptions.Compiled | RegexOptions.Singleline, RegexTimeout)),

        // Hex-encoded instructions
        ("EncodedPayload", "Hex-encoded content block",
            new(@"(?:\\x[0-9a-fA-F]{2}){8,}",
                RegexOptions.Compiled, RegexTimeout)),

        // Unicode escape sequences hiding payloads
        ("EncodedPayload", "Unicode escape sequence block",
            new(@"(?:\\u[0-9a-fA-F]{4}){6,}",
                RegexOptions.Compiled, RegexTimeout)),

        // HTML entities hiding payloads
        ("EncodedPayload", "HTML entity encoded content",
            new(@"(?:&#(?:x[0-9a-fA-F]{2,4}|\d{2,5});){6,}",
                RegexOptions.Compiled, RegexTimeout)),

        // ROT13 encoded instructions (common obfuscation)
        ("Obfuscation", "ROT13 decode instruction",
            new(@"(?i)(?:rot13|caesar)\s*[:(]\s*[a-zA-Z]{10,}",
                RegexOptions.Compiled, RegexTimeout)),

        // Fullwidth character obfuscation (U+FF00-U+FFEF used to bypass keyword detection)
        ("Obfuscation", "Fullwidth character obfuscation",
            new(@"[\uFF00-\uFFEF]{4,}",
                RegexOptions.Compiled, RegexTimeout)),
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

    public ToolResultGuardrailRule(ToolResultGuardrailOptions? options = null)
    {
        _options = options ?? new();
    }

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
        var sanitizedResults = _options.Action == ToolResultAction.Sanitize
            ? new List<ToolResultEntry>()
            : null;

        foreach (var result in toolResults)
        {
            if (_options.SkippedTools.Contains(result.ToolName))
            {
                sanitizedResults?.Add(result);
                continue;
            }

            if (string.IsNullOrWhiteSpace(result.Content))
            {
                sanitizedResults?.Add(result);
                continue;
            }

            var riskLevel = GetRiskLevel(result);
            var content = result.Content;

            // Pre-process: strip Unicode control characters if enabled
            if (_options.StripUnicodeControl)
            {
                content = StripControlCharacters(content);
            }

            var resultViolations = new List<ToolResultViolation>();

            // Always check core patterns
            CheckPatterns(result.ToolName, content, CorePatterns, resultViolations);

            // Check medium-risk patterns for medium and high risk tools
            if (riskLevel >= ToolRiskLevel.Medium)
            {
                CheckPatterns(result.ToolName, content, MediumRiskPatterns, resultViolations);
            }

            // Check high-risk patterns for high risk tools
            if (riskLevel >= ToolRiskLevel.High)
            {
                CheckPatterns(result.ToolName, content, HighRiskPatterns, resultViolations);
            }

            // Check custom patterns
            foreach (var (category, description, pattern) in _options.CustomPatterns)
            {
                var match = pattern.Match(content);
                if (match.Success)
                {
                    resultViolations.Add(new ToolResultViolation
                    {
                        ToolName = result.ToolName,
                        Category = category,
                        Description = description,
                        MatchedText = TruncateMatch(match.Value)
                    });
                }
            }

            violations.AddRange(resultViolations);

            if (sanitizedResults != null)
            {
                if (resultViolations.Count > 0)
                {
                    var sanitized = SanitizeContent(content, riskLevel);
                    sanitizedResults.Add(new ToolResultEntry
                    {
                        ToolName = result.ToolName,
                        Content = sanitized,
                        RiskLevel = result.RiskLevel,
                        Metadata = result.Metadata
                    });
                }
                else
                {
                    sanitizedResults.Add(result);
                }
            }
        }

        if (violations.Count > 0)
        {
            context.Properties[ViolationsKey] = violations;

            if (_options.Action == ToolResultAction.Sanitize && sanitizedResults != null)
            {
                context.Properties[SanitizedResultsKey] = sanitizedResults;

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

        return ValueTask.FromResult(GuardrailResult.Passed());
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

    private static void CheckPatterns(
        string toolName,
        string content,
        (string Category, string Description, Regex Pattern)[] patterns,
        List<ToolResultViolation> violations)
    {
        foreach (var (category, description, pattern) in patterns)
        {
            try
            {
                var match = pattern.Match(content);
                if (match.Success)
                {
                    violations.Add(new ToolResultViolation
                    {
                        ToolName = toolName,
                        Category = category,
                        Description = description,
                        MatchedText = TruncateMatch(match.Value)
                    });
                }
            }
            catch (RegexMatchTimeoutException)
            {
                // Pattern timed out - skip it rather than blocking legitimate content
            }
        }
    }

    private string SanitizeContent(string content, ToolRiskLevel riskLevel)
    {
        var replacement = _options.SanitizationReplacement;
        var sanitized = content;

        // Apply core patterns
        foreach (var (_, _, pattern) in CorePatterns)
        {
            try
            {
                sanitized = pattern.Replace(sanitized, replacement);
            }
            catch (RegexMatchTimeoutException) { }
        }

        if (riskLevel >= ToolRiskLevel.Medium)
        {
            foreach (var (_, _, pattern) in MediumRiskPatterns)
            {
                try
                {
                    sanitized = pattern.Replace(sanitized, replacement);
                }
                catch (RegexMatchTimeoutException) { }
            }
        }

        if (riskLevel >= ToolRiskLevel.High)
        {
            foreach (var (_, _, pattern) in HighRiskPatterns)
            {
                try
                {
                    sanitized = pattern.Replace(sanitized, replacement);
                }
                catch (RegexMatchTimeoutException) { }
            }
        }

        // Apply custom patterns
        foreach (var (_, _, pattern) in _options.CustomPatterns)
        {
            try
            {
                sanitized = pattern.Replace(sanitized, replacement);
            }
            catch (RegexMatchTimeoutException) { }
        }

        return sanitized;
    }

    private static string StripControlCharacters(string text)
    {
        // Remove zero-width and invisible Unicode characters that could be used to hide payloads
        return Regex.Replace(text, @"[\u200B\u200C\u200D\u2060\uFEFF\u00AD\u200E\u200F\u202A-\u202E\u2066-\u2069]", "",
            RegexOptions.Compiled, TimeSpan.FromMilliseconds(100));
    }

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
