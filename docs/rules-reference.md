# Rule Reference

Rules execute in order of their `Order` property (lower = first). Cheap regex/local checks run before expensive LLM calls.

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

## Prompt Injection Detection (LLM)

`.BlockPromptInjectionWithLlm(chatClient, options?)`

Order 15, Input phase. Uses `IChatClient` as an LLM-as-judge classifier. Catches sophisticated attacks regex misses: narrative smuggling, meta-prompting, cognitive overload, multi-chain attacks.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| SystemPrompt | `string?` | null | Custom system prompt override (null = built-in template) |
| IncludeClassification | `bool` | true | Return structured threat classification metadata |

When `IncludeClassification` is true, blocked results include `Metadata` with:
- `technique` — e.g. `direct_override`, `narrative_smuggling`, `cognitive_overload`, `russian_doll`
- `intent` — e.g. `jailbreak`, `system_prompt_leak`, `data_extraction`
- `evasion` — e.g. `none`, `base64`, `hex`, `reversed`, `unicode`
- `confidence` — `high`, `medium`, or `low`

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

`.BlockHarmfulContent(maxSeverity)`

Order 50, Both phases.

Requires an `IContentSafetyClassifier`. Use `AgentGuard.Azure` for Azure AI Content Safety integration.

## Output/Input Validation

`.ValidateOutput(predicate, message)` / `.ValidateInput(predicate, message)`

Order 100. Simple predicate-based assertions.

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
1. **Regex patterns** — `PromptInjectionRule` covers the techniques that can be reliably detected via pattern matching
2. **LLM prompt templates** — `LlmPromptInjectionRule` enumerates all technique families and evasion methods to give the LLM classifier precise conceptual anchors
3. **Input normalization** — `InputNormalizationRule` decodes the most common evasion encodings before any other rule evaluates the text
