# Rule Reference

## Prompt Injection Detection

`.BlockPromptInjection(sensitivity)`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| Sensitivity | `Sensitivity` | Medium | Low / Medium / High |
| CustomPatterns | `IList<string>` | [] | Additional regex patterns |

## PII Redaction

`.RedactPII(categories, replacement)`

Categories: `Email`, `Phone`, `SSN`, `CreditCard`, `IpAddress`, `DateOfBirth`, `Default`, `All`

## Topic Boundary Enforcement

`.EnforceTopicBoundary(topics...)` or `.EnforceTopicBoundary(threshold, topics...)`

| Option | Type | Default |
|--------|------|---------|
| SimilarityThreshold | float | 0.3 |
| AllowKeywordFallback | bool | true |

## Token Limits

`.LimitInputTokens(max, strategy)` / `.LimitOutputTokens(max, strategy)`

Strategies: `Reject`, `Truncate`, `Warn`

## Content Safety

`.BlockHarmfulContent(maxSeverity)`

Requires an `IContentSafetyClassifier`. Use `AgentGuard.Azure` for production.

## Output/Input Validation

`.ValidateOutput(predicate, message)` / `.ValidateInput(predicate, message)`
