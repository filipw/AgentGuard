# Rule Reference

Rules execute in order of their `Order` property (lower = first). Cheap regex/local checks run before expensive LLM calls.

## Sensible Defaults

`.UseDefaults()` (requires `AgentGuard.Onnx` package)

Wires up a solid baseline that works fully offline with no additional configuration:

```csharp
using AgentGuard.Onnx;

var policy = new GuardrailPolicyBuilder()
    .UseDefaults()    // equivalent to the rules below
    .Build();

// Expands to:
//   .NormalizeInput()                    (order 5)
//   .BlockPromptInjection()             (order 10)
//   .BlockPromptInjectionWithDefender() (order 11)
//   .RedactPII()                        (order 20)
//   .DetectSecrets()                    (order 22)
//   .GuardToolCalls()                   (order 45)
//   .GuardToolResults()                 (order 47)
```

You can chain additional rules after `UseDefaults()` to layer on more protection (e.g. topic boundary, LLM-based rules, token limits).

## Input Normalization

`.NormalizeInput(options?)`

Decodes common evasion encodings before downstream rules see the text. Runs at order 5, before all other rules.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| DecodeBase64 | `bool` | true | Detect and decode base64-encoded segments |
| DecodeHex | `bool` | true | Decode hex escape sequences (`\x69\x67...`) |
| DetectReversedText | `bool` | true | Detect and reverse reversed text blocks |
| NormalizeUnicode | `bool` | true | Normalize Unicode homoglyphs (Cyrillic/Greek → Latin) |
| MinBase64Length | `int` | 16 | Minimum base64 segment length to attempt decoding |

Decoded content is appended with a `[DECODED]` marker so downstream rules can evaluate both the original and decoded forms.

## Prompt Injection Detection (Regex)

`.BlockPromptInjection(sensitivity)`

Order 10, Input phase. Patterns informed by the [Arcanum Prompt Injection Taxonomy](https://github.com/Arcanum-Sec/arc_pi_taxonomy).

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| Sensitivity | `Sensitivity` | Medium | Low / Medium / High |
| CustomPatterns | `IList<string>` | [] | Additional regex patterns |

**Sensitivity tiers:**

| Tier | Detects |
|------|---------|
| Low (Core) | Direct instruction override, role/persona hijacking, end sequence injection, variable expansion |
| Medium (+Medium) | + System prompt extraction, jailbreak keywords, rule addition/modification |
| High (+High) | + Framing attacks (hypothetical/fictional contexts), inversion/double-negative extraction |

## Prompt Injection Detection (ONNX - StackOne Defender)

`.BlockPromptInjectionWithDefender()` or `.BlockPromptInjectionWithDefender(options)`

Order 11, Input phase. Uses the [StackOne Defender](https://github.com/StackOneHQ/defender) fine-tuned MiniLM-L6-v2 ONNX model (~22 MB, int8 quantized) for ML-based binary classification. **F1 ~0.97** on adversarial benchmarks. Fast (~8 ms), accurate, fully offline. The model is **bundled with the NuGet package** - no separate download required.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| Threshold | `float` | 0.5 | Confidence threshold (0.0–1.0) for injection classification |
| MaxTokenLength | `int` | 256 | Maximum input token length (truncated if longer) |
| IncludeConfidence | `bool` | true | Include confidence score in result metadata |
| ModelPath | `string?` | null | Custom model path (if null, bundled model is used) |
| VocabPath | `string?` | null | Custom vocab path (if null, bundled vocab is used) |

When blocked, result metadata includes:
- `confidence` - injection probability (0.0–1.0)
- `model` - `"stackone-defender-minilm-v2"`
- `threshold` - the configured threshold

```csharp
using AgentGuard.Onnx;

// Zero-config - bundled model, no download needed
builder.BlockPromptInjectionWithDefender()

// Or with custom threshold
builder.BlockPromptInjectionWithDefender(new DefenderPromptInjectionOptions { Threshold = 0.8f })
```

## Prompt Injection Detection (ONNX - DeBERTa v3)

`.BlockPromptInjectionWithDeberta(options)` or `.BlockPromptInjectionWithDeberta(modelPath, tokenizerPath, threshold)`

Order 12, Input phase. Uses a fine-tuned DeBERTa v3 ONNX model (`protectai/deberta-v3-base-prompt-injection-v2`) for ML-based binary classification. Fully offline, ~100ms inference. Requires separate model download. For most use cases, prefer the Defender model above.

**Setup:** Download the model from HuggingFace using the included script:
```bash
./eng/download-onnx-model.sh
# Downloads model.onnx (~370MB) + spm.model (~2MB) to ./models/deberta-v3-prompt-injection/
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| ModelPath | `string` | *(required)* | Path to the ONNX model file |
| TokenizerPath | `string` | *(required)* | Path to the SentencePiece model file (spm.model) |
| Threshold | `float` | 0.5 | Confidence threshold (0.0–1.0) for injection classification |
| MaxTokenLength | `int` | 512 | Maximum input token length (truncated if longer) |
| IncludeConfidence | `bool` | true | Include confidence score in result metadata |

**Multi-tier detection:**
```csharp
using AgentGuard.Onnx;

builder.BlockPromptInjection()              // tier 1: regex (order 10)
    .BlockPromptInjectionWithDefender()         // tier 2: Defender ML (order 11, bundled)
    .BlockPromptInjectionWithRemoteClassifier(...)  // tier 3: remote ML (order 13)
    .BlockPromptInjectionWithLlm(chatClient) // tier 4: LLM (order 15)
```

## Prompt Injection Detection (Remote ML)

`.BlockPromptInjectionWithRemoteClassifier(endpointUrl)` or `.BlockPromptInjectionWithRemoteClassifier(classifier, options?)`

Order 13, Input phase. Calls an external model server for ML-based classification. Designed for SOTA models like [Sentinel-v2](https://huggingface.co/rogue-security/prompt-injection-jailbreak-sentinel-v2) (Qwen3-0.6B, F1 ~0.957, 32K context). Requires `AgentGuard.RemoteClassifier` package.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| EndpointUrl | `string` | *(required)* | URL of the classification endpoint |
| ApiKey | `string?` | null | Optional Bearer token for authenticated endpoints |
| ModelName | `string?` | null | Model name for result metadata |
| RequestFormat | `HttpClassifierRequestFormat` | HuggingFace | Request/response format (HuggingFace or Simple) |
| InjectionLabels | `ISet<string>` | jailbreak, injection, malicious, unsafe, INJECTION | Labels indicating injection |
| Threshold | `float` | 0.5 | Confidence threshold (0.0–1.0) |
| OnError | `ErrorBehavior` | FailOpen | What to do on error: FailOpen (pass), Warn (pass + metadata), FailClosed (block) |
| Timeout | `TimeSpan` | 10s | HTTP request timeout |

When blocked, result metadata includes:
- `label` - the predicted label (e.g. "jailbreak")
- `confidence` - classification score (0.0–1.0)
- `model` - model name (if configured)
- `threshold` - the configured threshold

**Setting up a Sentinel-v2 endpoint:**
```bash
# FastAPI server wrapping the transformers pipeline
pip install transformers torch fastapi uvicorn
# See samples/RemoteClassifier/ for a complete server example
```

```csharp
using AgentGuard.RemoteClassifier;

var policy = new GuardrailPolicyBuilder()
    .BlockPromptInjection()                                  // tier 1: regex
    .BlockPromptInjectionWithRemoteClassifier(               // tier 2: remote ML
        "http://localhost:8000/classify",
        modelName: "sentinel-v2",
        threshold: 0.7f)
    .BlockPromptInjectionWithLlm(chatClient)                 // tier 3: LLM
    .Build();
```

---

## Prompt Injection Detection (LLM)

`.BlockPromptInjectionWithLlm(chatClient, options?)`

Order 15, Input phase. Uses `IChatClient` as an LLM-as-judge classifier. Catches sophisticated attacks regex misses: narrative smuggling, meta-prompting, cognitive overload, multi-chain attacks.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| SystemPrompt | `string?` | null | Custom system prompt override (null = built-in template) |
| IncludeClassification | `bool` | true | Return structured threat classification metadata |

When `IncludeClassification` is true, blocked results include `Metadata` with:
- `technique` - e.g. `direct_override`, `narrative_smuggling`, `cognitive_overload`, `russian_doll`
- `intent` - e.g. `jailbreak`, `system_prompt_leak`, `data_extraction`
- `evasion` - e.g. `none`, `base64`, `hex`, `reversed`, `unicode`
- `confidence` - `high`, `medium`, or `low`

## PII Redaction (Regex)

`.RedactPII(categories, replacement)`

Order 20, Both phases.

Categories: `Email`, `Phone`, `SSN`, `CreditCard`, `IpAddress`, `DateOfBirth`, `Default`, `All`

| Option | Type | Default |
|--------|------|---------|
| Categories | `PiiCategory` | Default (Email, Phone, SSN, CreditCard) |
| Replacement | `string` | `[REDACTED]` |
| CustomPatterns | `IDictionary<string, string>` | {} |

## PII Detection (LLM)

`.DetectPIIWithLlm(chatClient, options?)`

Order 25, Both phases. Catches unstructured PII (names, addresses, contextual identifiers) that regex misses.

| Option | Type | Default |
|--------|------|---------|
| Action | `PiiAction` | Block |
| SystemPrompt | `string?` | null (built-in templates) |

`PiiAction.Block` returns a blocked result. `PiiAction.Redact` returns a modified result with the LLM's redacted version.

## Topic Boundary Enforcement (Keywords)

`.EnforceTopicBoundary(topics...)` or `.EnforceTopicBoundary(threshold, topics...)`

Order 30, Input phase.

| Option | Type | Default |
|--------|------|---------|
| SimilarityThreshold | float | 0.3 |
| AllowKeywordFallback | bool | true |

Supports pluggable `ITopicSimilarityProvider` for embedding-based matching.

## Topic Boundary Enforcement (LLM)

`.EnforceTopicBoundaryWithLlm(chatClient, topics...)`

Order 35, Input phase. Semantic topic classification that understands intent.

| Option | Type | Default |
|--------|------|---------|
| AllowedTopics | `IList<string>` | [] |
| SystemPrompt | `string?` | null (built-in template with `{topics}` placeholder) |

## Token Limits

`.LimitInputTokens(max, strategy)` / `.LimitOutputTokens(max, strategy)`

Order 40, Input or Output phase.

Strategies: `Reject`, `Truncate`, `Warn`

Uses `Microsoft.ML.Tokenizers` (cl100k_base) for accurate token counting.

## Content Safety

`.BlockHarmfulContent(maxSeverity)` or `.BlockHarmfulContent(options)` or `.BlockHarmfulContent(classifier, options?)`

Order 50, Both phases.

Requires an `IContentSafetyClassifier`. Use `AgentGuard.Azure` for Azure AI Content Safety integration.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| MaxAllowedSeverity | `ContentSafetySeverity` | Low | Threshold for blocking |
| Categories | `ContentSafetyCategory` | All | Which categories to check (Hate, Violence, SelfHarm, Sexual) |
| BlocklistNames | `IList<string>` | [] | Server-side blocklists to check against |
| HaltOnBlocklistHit | `bool` | false | Skip category analysis if blocklist matches (performance optimization) |

Blocklist matches are checked first and take precedence over category analysis. When a blocklist match is found, the result includes metadata with `blocklistName`, `blocklistItemText`, and `totalMatches`.

## Tool Result Guardrails (Indirect Injection)

`.GuardToolResults(options?)` or `.GuardToolResults(action)`

Order 47, Output phase. Detects indirect prompt injection in incoming tool call results - emails, documents, API responses - before they reach the LLM. Complements `ToolCallGuardrailRule` (which guards outbound arguments). Inspired by [StackOneHQ/defender](https://github.com/StackOneHQ/defender).

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| Action | `ToolResultAction` | Block | `Block` to reject, `Sanitize` to strip injections |
| ToolRiskProfiles | `IDictionary<string, ToolRiskLevel>` | {} | Per-tool risk overrides (Low/Medium/High) |
| SkippedTools | `ISet<string>` | {} | Tool names to skip entirely |
| StripUnicodeControl | `bool` | true | Strip zero-width and invisible Unicode characters before evaluation |
| DetectEncodedPayloads | `bool` | true | Detect base64-encoded injection payloads |
| SanitizationReplacement | `string` | `[FILTERED]` | Replacement text when sanitizing |
| CustomPatterns | `IReadOnlyList<(string, string, Regex)>` | [] | Additional (category, description, pattern) tuples |

**Three-tier risk-based detection:**

| Tier | Risk Level | Patterns Checked |
|------|-----------|-----------------|
| Core | All tools | Role hijacking, instruction override, ChatML/XML token injection, HTML comment injection, zero-width chars, data exfiltration URLs, prompt leak instructions |
| Medium | Medium + High | Markdown hidden text, `[INST]` tags, hex-encoded content |
| High | High only | Action directives, social engineering, delimiter manipulation, persona hijacking, base64-encoded instructions |

**Built-in tool risk profiles:**

| Risk Level | Default Tools |
|-----------|--------------|
| High | gmail, email, outlook, slack, teams, discord, chat, message, sms |
| Medium | search, web_search, browse, read_file, get_document, github, jira, confluence |
| Low | calculator, get_weather, get_time |

Tools not in the profile default to Medium. Tool names containing "email", "mail", "message", "chat", "slack", or "sms" are heuristically classified as High.

Place tool results in `GuardrailContext.Properties["ToolResults"]` as `IReadOnlyList<ToolResultEntry>`. When action is Sanitize, sanitized results are written to `Properties["SanitizedToolResults"]`. Violations are stored in `Properties["ToolResultViolations"]`.

---

## Output/Input Validation

`.ValidateOutput(predicate, message)` / `.ValidateInput(predicate, message)`

Order 100. Simple predicate-based assertions.

## Output Policy Enforcement (LLM)

`.EnforceOutputPolicy(chatClient, policyDescription)` or `.EnforceOutputPolicyWithLlm(chatClient, options)`

Checks whether the agent's response violates a custom policy constraint. Useful for brand safety, compliance, and operational guardrails.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| PolicyDescription | `string` | *(required)* | Natural language description of the policy to enforce |
| Action | `OutputPolicyAction` | Block | `Block` to reject, `Warn` to pass with metadata |
| SystemPrompt | `string?` | *(built-in)* | Custom system prompt (use `{policy}` placeholder) |

- **Order**: 55, **Phase**: Output
- Response format: `COMPLIANT` or `VIOLATION|reason:<reason>`
- When `Action = Warn`, the result passes but includes `Metadata["violation_reason"]` and `Metadata["policy"]`

---

## Groundedness Checking (LLM)

`.CheckGroundedness(chatClient)` or `.CheckGroundednessWithLlm(chatClient, options?)`

Detects hallucinated facts and claims not supported by the conversation context. Uses `GuardrailContext.Messages` to provide conversation history to the LLM.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| Action | `GroundednessAction` | Block | `Block` to reject, `Warn` to pass with metadata |
| SystemPrompt | `string?` | *(built-in)* | Custom system prompt (use `{context}` placeholder) |

- **Order**: 65, **Phase**: Output
- Response format: `GROUNDED` or `UNGROUNDED|claim:<ungrounded claim>`
- Common knowledge facts are considered grounded even without conversation context
- When `Action = Warn`, the result passes but includes `Metadata["ungrounded_claim"]`

---

## Copyright Detection (LLM)

`.CheckCopyright(chatClient)` or `.CheckCopyrightWithLlm(chatClient, options?)`

Detects verbatim or near-verbatim reproduction of copyrighted material (song lyrics, book passages, articles, restrictively-licensed code).

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| Action | `CopyrightAction` | Block | `Block` to reject, `Warn` to pass with metadata |
| SystemPrompt | `string?` | *(built-in)* | Custom system prompt override |

- **Order**: 75, **Phase**: Output
- Response format: `CLEAN` or `COPYRIGHT|source:<source>|type:<lyrics|book|article|code|poem|speech|other>`
- Short quotes (<15 words) for commentary are acceptable and not flagged
- Public domain works and common phrases are not flagged
- When `Action = Warn`, the result passes but includes `Metadata["copyright_source"]` and `Metadata["copyright_type"]`

---

## Workflow Guardrails

`AgentGuard.AgentFramework` includes workflow guardrails that apply at MAF workflow step boundaries using the decorator pattern.

### `.WithGuardrails()` Extension Methods

Wraps `Executor<TInput>` or `Executor<TInput, TOutput>` with a `GuardedExecutor` that runs guardrails before/after the inner executor.

| Executor Type | Input Guardrails | Output Guardrails | On Block |
|---------------|-----------------|-------------------|----------|
| `Executor<TInput>` (void) | Yes | No | Throws `GuardrailViolationException` |
| `Executor<TInput, TOutput>` (typed) | Yes | Yes | Throws `GuardrailViolationException` |

```csharp
// Builder overload
var guarded = executor.WithGuardrails(b => b.BlockPromptInjection().RedactPII());

// Pre-built policy overload
var guarded = executor.WithGuardrails(existingPolicy);

// With options (custom text extractor, logger)
var guarded = executor.WithGuardrails(b => b.RedactPII(),
    new GuardedExecutorOptions { TextExtractor = myExtractor });
```

### `ITextExtractor`

Bridges typed workflow messages to strings for guardrail evaluation. `DefaultTextExtractor` handles:
- `string` → the string itself
- `ChatMessage` → `.Text`
- `AgentResponse` → last assistant message text
- `IEnumerable<ChatMessage>` → last message text
- Objects with a public `Text` property → reflection
- Fallback → `ToString()`

### `GuardrailViolationException`

Thrown when a guardrail blocks within a workflow executor. MAF surfaces this as `ExecutorFailedEvent`.

| Property | Type | Description |
|----------|------|-------------|
| `ViolationResult` | `GuardrailResult` | The blocking result (rule name, reason, severity) |
| `Phase` | `GuardrailPhase` | `Input` or `Output` |
| `ExecutorId` | `string` | ID of the inner executor that was guarded |

### Text Reconstruction

When a guardrail modifies text (e.g. PII redaction), the modified text is reconstructed back into the message type:
- `string` → replaced directly
- `ChatMessage` → new message with same role, modified text
- Other types → passed through unchanged (modification cannot be applied)

---

## Custom Rules

`.AddRule(rule)` or `.AddRule(name, phase, evaluate, order)`

Add any `IGuardrailRule` implementation or a delegate-based rule.

---

## Threat Model Reference

AgentGuard's prompt injection detection is informed by the [Arcanum Prompt Injection Taxonomy](https://github.com/Arcanum-Sec/arc_pi_taxonomy) (CC BY 4.0, Jason Haddix / Arcanum Information Security), which classifies attacks into:

- **12 Attack Techniques**: direct instruction override, role/persona hijacking, system prompt extraction, meta-prompting, narrative smuggling, cognitive overload, russian doll/multi-chain, rule addition, framing, inversion, end sequence injection, variable expansion
- **13 Attack Intents**: jailbreak, system prompt leak, data extraction, denial of service, tool enumeration, and more
- **20 Evasion Methods**: base64, hex, reversed text, Unicode homoglyphs, emoji, cipher, JSON/XML wrapping, and more

The taxonomy is used at three levels:
1. **Regex patterns** - `PromptInjectionRule` covers the techniques that can be reliably detected via pattern matching
2. **LLM prompt templates** - `LlmPromptInjectionRule` enumerates all technique families and evasion methods to give the LLM classifier precise conceptual anchors
3. **Input normalization** - `InputNormalizationRule` decodes the most common evasion encodings before any other rule evaluates the text
