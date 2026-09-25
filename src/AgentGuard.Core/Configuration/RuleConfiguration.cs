namespace AgentGuard.Core.Configuration;

/// <summary>
/// Configuration for a single guardrail rule. The <see cref="Type"/> property determines
/// which other properties are relevant. Unrecognized types throw at startup.
/// </summary>
public sealed class RuleConfiguration
{
    /// <summary>
    /// Rule type. The built-in set is: InputNormalization, PromptInjection,
    /// DefenderPromptInjection, DebertaPromptInjection, PiiRedaction, Secrets, Retrieval,
    /// ToolCallGuardrail, ToolResultGuardrail, TokenLimit, ContentSafety, LlmPromptInjection,
    /// LlmPiiDetection, LlmTopicBoundary, LlmOutputPolicy, LlmGroundedness, LlmCopyright.
    /// Types outside that set are handed to a registered <see cref="IGuardrailRuleFactory"/>;
    /// <c>RemotePii</c> and <c>AzurePii</c> ship as factories in their own packages. A type no
    /// factory claims throws at startup.
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
    /// <summary>Replacement text for redacted PII. Default: null, which replaces each entity with its <c>&lt;ENTITY_TYPE&gt;</c> tag.</summary>
    public string? Replacement { get; set; }
    /// <summary>
    /// Country packs to enable in addition to the generic recognizers and the always-on US pack, by
    /// ISO 3166-1 alpha-2 code (e.g. uk, de, in, it, es). When empty, only generic + US run.
    /// </summary>
    public List<string>? Countries { get; set; }

    // --- LlmTopicBoundary ---
    /// <summary>List of allowed topic names. Required for LlmTopicBoundary.</summary>
    public List<string>? AllowedTopics { get; set; }

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

    // --- ONNX prompt injection ---
    /// <summary>
    /// Path to the ONNX model file. Required for DebertaPromptInjection. For OnnxPromptInjection it
    /// selects the bring-your-own-model rule; leave it unset to use the bundled Defender model.
    /// </summary>
    public string? ModelPath { get; set; }
    /// <summary>Path to the SentencePiece tokenizer file. Required alongside <see cref="ModelPath"/>.</summary>
    public string? TokenizerPath { get; set; }
    /// <summary>
    /// Confidence threshold (0.0–1.0). Default: 0.75 for the bundled Defender model (its calibrated
    /// main-head operating point), 0.5 for a bring-your-own DeBERTa model.
    /// </summary>
    public float? Threshold { get; set; }

    // --- LlmPromptInjection ---
    /// <summary>Include structured threat classification. Default: true.</summary>
    public bool? IncludeClassification { get; set; }

    // --- Secrets ---
    /// <summary>Secret action: Block or Redact. Default: Block.</summary>
    public string? SecretAction { get; set; }

    // --- ToolCallGuardrail ---
    /// <summary>Injection categories: Default, All, or a comma-separated list (SqlInjection, Ssrf, ...).</summary>
    public string? Categories { get; set; }

    // --- ToolResultGuardrail ---
    /// <summary>Tool result action: Block or Sanitize. Default: Block.</summary>
    public string? Action { get; set; }
    /// <summary>Strip invisible Unicode characters from tool results. Default: true.</summary>
    public bool? StripUnicodeControl { get; set; }

    // --- Retrieval ---
    /// <summary>Detect prompt injection in retrieved chunks. Default: true.</summary>
    public bool? DetectPromptInjection { get; set; }
    /// <summary>Detect secrets in retrieved chunks. Default: true.</summary>
    public bool? DetectSecrets { get; set; }
    /// <summary>Detect PII in retrieved chunks. Default: false.</summary>
    public bool? DetectPii { get; set; }
    /// <summary>Retrieval filter action: Remove or Sanitize. Default: Remove.</summary>
    public string? RetrievalAction { get; set; }

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
