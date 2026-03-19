namespace AgentGuard.Hosting.Configuration;

/// <summary>
/// Root configuration for AgentGuard policies, bound from appsettings.json.
/// </summary>
public sealed class AgentGuardConfiguration
{
    /// <summary>
    /// Configuration for the default policy.
    /// </summary>
    public PolicyConfiguration? DefaultPolicy { get; set; }

    /// <summary>
    /// Named policies, keyed by policy name.
    /// </summary>
    public Dictionary<string, PolicyConfiguration> Policies { get; set; } = [];
}

/// <summary>
/// Configuration for a single guardrail policy.
/// </summary>
public sealed class PolicyConfiguration
{
    /// <summary>
    /// Ordered list of rules to apply.
    /// </summary>
    public List<RuleConfiguration> Rules { get; set; } = [];

    /// <summary>
    /// Optional custom violation message. If set, blocked requests receive this message.
    /// </summary>
    public string? ViolationMessage { get; set; }
}

/// <summary>
/// Configuration for a single guardrail rule. The <see cref="Type"/> property determines
/// which other properties are relevant. Unrecognized types throw at startup.
/// </summary>
public sealed class RuleConfiguration
{
    /// <summary>
    /// Rule type. One of: InputNormalization, PromptInjection, PiiRedaction,
    /// TopicBoundary, TokenLimit, ContentSafety, LlmPromptInjection, LlmPiiDetection, LlmTopicBoundary.
    /// </summary>
    public string Type { get; set; } = "";

    // --- PromptInjection ---
    /// <summary>Sensitivity level: Low, Medium, or High. Default: Medium.</summary>
    public string? Sensitivity { get; set; }

    // --- PiiRedaction ---
    /// <summary>PII categories: Default, All, or comma-separated (Email, Phone, SSN, CreditCard, IpAddress, DateOfBirth).</summary>
    public string? Categories { get; set; }
    /// <summary>Replacement text for redacted PII. Default: [REDACTED].</summary>
    public string? Replacement { get; set; }

    // --- TopicBoundary / LlmTopicBoundary ---
    /// <summary>List of allowed topic names.</summary>
    public List<string>? AllowedTopics { get; set; }
    /// <summary>Similarity threshold for topic matching (0.0–1.0). Default: 0.3.</summary>
    public float? SimilarityThreshold { get; set; }

    // --- TokenLimit ---
    /// <summary>Maximum token count.</summary>
    public int? MaxTokens { get; set; }
    /// <summary>Phase: Input or Output. Default: Input.</summary>
    public string? Phase { get; set; }
    /// <summary>Overflow strategy: Reject, Truncate, or Warn. Default: Reject for input, Truncate for output.</summary>
    public string? OverflowStrategy { get; set; }

    // --- ContentSafety ---
    /// <summary>Maximum allowed severity: Safe, Low, Medium. Default: Low.</summary>
    public string? MaxAllowedSeverity { get; set; }
    /// <summary>Server-side blocklist names to check.</summary>
    public List<string>? BlocklistNames { get; set; }
    /// <summary>Whether to halt on first blocklist match. Default: false.</summary>
    public bool? HaltOnBlocklistHit { get; set; }

    // --- InputNormalization ---
    /// <summary>Decode base64-encoded content. Default: true.</summary>
    public bool? DecodeBase64 { get; set; }
    /// <summary>Decode hex-encoded content. Default: true.</summary>
    public bool? DecodeHex { get; set; }
    /// <summary>Detect reversed text. Default: true.</summary>
    public bool? DetectReversedText { get; set; }
    /// <summary>Normalize Unicode homoglyphs. Default: true.</summary>
    public bool? NormalizeUnicode { get; set; }

    // --- LlmPiiDetection ---
    /// <summary>PII action: Block or Redact. Default: Redact.</summary>
    public string? PiiAction { get; set; }

    // --- LLM rules (shared) ---
    /// <summary>Custom system prompt for LLM rules. Optional.</summary>
    public string? SystemPrompt { get; set; }

    // --- LlmPromptInjection ---
    /// <summary>Include structured threat classification. Default: true.</summary>
    public bool? IncludeClassification { get; set; }
}
