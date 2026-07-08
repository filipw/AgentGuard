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
    /// Rule type. One of: InputNormalization, PromptInjection, PiiRedaction, RemotePii, AzurePii,
    /// TopicBoundary, OutputTopicBoundary, TokenLimit, ContentSafety, LlmPromptInjection, LlmPiiDetection,
    /// LlmTopicBoundary, LlmOutputPolicy, LlmGroundedness, LlmCopyright.
    /// </summary>
    public string Type { get; set; } = "";

    // --- PromptInjection ---
    /// <summary>Sensitivity level: Low, Medium, or High. Default: Medium.</summary>
    public string? Sensitivity { get; set; }

    // --- PiiRedaction / RemotePii / AzurePii ---
    /// <summary>
    /// PII entity types to detect (e.g. EMAIL_ADDRESS, PHONE_NUMBER, US_SSN, CREDIT_CARD, IBAN_CODE,
    /// CRYPTO, IP_ADDRESS, URL, MAC_ADDRESS, US_ITIN). When empty, all supported entities are detected
    /// (PiiRedaction only). For RemotePii / AzurePii this is the set the remote detector supports
    /// (e.g. PERSON, ADDRESS) and is required - there is no "detect everything" default for a remote call.
    /// </summary>
    public List<string>? Entities { get; set; }
    /// <summary>Replacement text for redacted PII. Default: [REDACTED].</summary>
    public string? Replacement { get; set; }
    /// <summary>
    /// Country packs to enable in addition to the generic recognizers and the always-on US pack, by
    /// ISO 3166-1 alpha-2 code (e.g. uk, de, in, it, es). When empty, only generic + US run.
    /// </summary>
    public List<string>? Countries { get; set; }

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

    // --- OnnxPromptInjection ---
    /// <summary>Path to the ONNX model file (required for OnnxPromptInjection).</summary>
    public string? ModelPath { get; set; }
    /// <summary>Path to the HuggingFace tokenizer.json file (required for OnnxPromptInjection).</summary>
    public string? TokenizerPath { get; set; }
    /// <summary>Confidence threshold (0.0–1.0) for ONNX prompt injection. Default: 0.5.</summary>
    public float? Threshold { get; set; }

    // --- LlmPromptInjection ---
    /// <summary>Include structured threat classification. Default: true.</summary>
    public bool? IncludeClassification { get; set; }

    // --- OutputTopicBoundary ---
    /// <summary>Output topic action: Block or Warn. Default: Block.</summary>
    public string? OutputTopicAction { get; set; }

    // --- LlmOutputPolicy ---
    /// <summary>Natural language description of the policy to enforce (required for LlmOutputPolicy).</summary>
    public string? PolicyDescription { get; set; }
    /// <summary>Output policy action: Block or Warn. Default: Block.</summary>
    public string? OutputPolicyAction { get; set; }

    // --- LlmGroundedness ---
    /// <summary>Groundedness action: Block or Warn. Default: Block.</summary>
    public string? GroundednessAction { get; set; }

    // --- LlmCopyright ---
    /// <summary>Copyright action: Block or Warn. Default: Block.</summary>
    public string? CopyrightAction { get; set; }

    // --- RemotePii / AzurePii (shared) ---
    /// <summary>
    /// Base URL of the remote detector (RemotePii), or the Azure AI Language resource endpoint
    /// (AzurePii). Required for both.
    /// </summary>
    public string? Endpoint { get; set; }
    /// <summary>Per-request timeout in seconds (RemotePii / AzurePii). Default: 10.</summary>
    public int? TimeoutSeconds { get; set; }
    /// <summary>
    /// When true (default), a remote/Azure failure is swallowed and local-only recognizers still
    /// redact what they can (RemotePii / AzurePii). When false, the failure propagates.
    /// </summary>
    public bool? FailOpen { get; set; }

    // --- RemotePii ---
    /// <summary>Optional HTTP header name used to authenticate against the remote endpoint (RemotePii).</summary>
    public string? AuthHeaderName { get; set; }
    /// <summary>The value sent for <see cref="AuthHeaderName"/> (RemotePii).</summary>
    public string? AuthHeaderValue { get; set; }

    // --- AzurePii ---
    /// <summary>
    /// API key for the Azure AI Language resource (AzurePii), sent as <c>Ocp-Apim-Subscription-Key</c>.
    /// Required unless <see cref="UseManagedIdentity"/> is true.
    /// </summary>
    public string? SubscriptionKey { get; set; }
    /// <summary>
    /// Authenticate to Azure AI Language via <c>DefaultAzureCredential</c> instead of a subscription
    /// key (AzurePii). Default: false.
    /// </summary>
    public bool? UseManagedIdentity { get; set; }
    /// <summary>Azure AI Language processing domain: None or Phi (AzurePii). Default: None.</summary>
    public string? Domain { get; set; }
}
