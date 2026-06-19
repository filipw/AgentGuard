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
//   .RedactPii()                        (order 20)
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

Order 11, Input phase. Uses the [StackOne Defender](https://github.com/StackOneHQ/defender) fine-tuned multi-head MiniLM-L6 ONNX model (minilm-multihead-v5, ~22 MB, int8 quantized). Fast (~8 ms), fully offline, **bundled with the NuGet package** - no separate download required.

The model emits two temperature-calibrated scores: a **main** injection score and an **aux** "directed at a human reader" score. Input is blocked when `main >= MainThreshold AND aux < AuxThreshold` - a high aux score **vetoes** the block. This rescues imperative-but-benign phrasings (e.g. "show me my orders", "list all my orders") that the older single-head model flagged as false positives.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| MainThreshold | `float` | 0.75 | Main-head block threshold (0.0–1.0) |
| AuxThreshold | `float` | 0.64 | Aux-head veto threshold (0.0–1.0); aux at or above this rescues the block |
| TemperatureT | `float` | 2.41 | Calibration temperature; each logit is divided by this before sigmoid |
| MaxTokenLength | `int` | 256 | Maximum input token length (truncated if longer) |
| IncludeConfidence | `bool` | true | Include main/aux scores in result metadata |
| ModelPath | `string?` | null | Custom model path (if null, bundled model is used) |
| VocabPath | `string?` | null | Custom vocab path (if null, bundled vocab is used) |

When blocked, result metadata includes:
- `mainScore` / `auxScore` - calibrated probabilities (0.0–1.0)
- `model` - `"stackone-defender-minilm-multihead-v5"`
- `mainThreshold` / `auxThreshold` / `temperatureT` - the configured decision parameters

```csharp
using AgentGuard.Onnx;

// Zero-config - bundled model, no download needed
builder.BlockPromptInjectionWithDefender()

// Or with a custom main-head threshold (raise to reduce false positives further)
builder.BlockPromptInjectionWithDefender(new DefenderPromptInjectionOptions { MainThreshold = 0.93f })
```

**Limitations.**

- **English-centric.** Trained mostly on English, the model over-fires on non-English benign input (e.g. ordinary German questions). For non-English users, raise `MainThreshold` for that segment rather than disabling the rule (see [Dynamic rule enabling](#dynamic-rule-enabling)). Tradeoff: a higher threshold also weakens detection of *native-language* attacks, so pair it with a multilingual classifier for real coverage.
- **Residual English imperatives.** A few "show me X" phrasings (e.g. "show me my account details") still block - confidently misscored ~90% with low aux, so no threshold short of ~0.9-0.93 rescues them, and that costs recall.

The default `MainThreshold` is **0.75** (within the F1-optimal plateau on a held-out jailbreak set: ~4× lower false-positive rate than 0.5 for a few points of recall). Raise toward 0.9/0.93 to cut false positives further at a recall cost.

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

## Prompt Injection Detection (ONNX - PIGuard)

`.BlockPromptInjectionWithPIGuard(options)` or `.BlockPromptInjectionWithPIGuard(modelPath, tokenizerPath, threshold)`

Order 12, Input phase. Uses the [PIGuard](https://huggingface.co/leolee99/PIGuard) DeBERTa v3 model (ACL 2025, MIT), trained with the "Mitigating Over-defense for Free" strategy. In AgentGuard's own measurements it keeps benign false positives low (over-defense comparable to the bundled Defender) while detecting **indirect / code-style injection far better** than Defender (BIPIA_code recall 96% vs 34%). Fully offline. A heavier model than Defender, so best used as a standalone guard or layered after it. See [`eng/piguard-eval/RESULTS.md`](../eng/piguard-eval/RESULTS.md) for the full benchmark.

**Setup:** Download the model from HuggingFace using the included script:
```bash
./eng/download-piguard-model.sh
# Downloads model.onnx (fp16 ~369MB) + spm.model to ./models/piguard/
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| ModelPath | `string` | *(required)* | Path to the PIGuard ONNX model file |
| TokenizerPath | `string` | *(required)* | Path to the DeBERTa v3 SentencePiece model (spm.model) |
| Threshold | `float` | 0.9 | Confidence threshold. The argmax default (0.5) over-blocks; 0.9 is the measured operating point |
| MaxTokenLength | `int` | 512 | Maximum input token length (truncated if longer) |
| IncludeConfidence | `bool` | true | Include confidence score in result metadata |

> The model is an ONNX export distributed at [`filip-w/PIGuard-onnx`](https://huggingface.co/filip-w/PIGuard-onnx).

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

## PII Detection & De-identification

`.RedactPii(options?)` or `.RedactPii(replacement, entities?)` (from `AgentGuard.Pii`)

Order 20, Both phases. Offline PII detection and anonymization using validated regex recognizers
with confidence scoring, overlap resolution, lemma-aware context score boosting, and configurable
anonymization operators. Inspired by the architecture of Microsoft Presidio (see THIRD_PARTY_NOTICES.txt).

**Generic entities (always on):** `CREDIT_CARD` (Luhn), `EMAIL_ADDRESS`, `IBAN_CODE` (mod-97),
`CRYPTO` (Bitcoin checksum), `IP_ADDRESS`, `URL`, `MAC_ADDRESS`, `PHONE_NUMBER` (libphonenumber).

**US pack (always on):** `US_SSN`, `US_ITIN`, `ABA_ROUTING_NUMBER` (checksum), `US_BANK_NUMBER`,
`US_DRIVER_LICENSE`, `US_PASSPORT`, `US_NPI` (Luhn), `US_MBI`, `MEDICAL_LICENSE` (DEA checksum).

**Country packs (opt-in via `Countries`):** enabling every national identifier at once inflates
false positives, so non-US packs are opt-in by ISO 3166-1 alpha-2 code:

- `uk`: `UK_NINO`, `UK_NHS` (mod-11), `UK_POSTCODE`, `UK_PASSPORT`, `UK_DRIVING_LICENCE`, `UK_VEHICLE_REGISTRATION`
- `de`: `DE_ID_CARD` (checksum), `DE_TAX_ID` (checksum), `DE_PASSPORT` (checksum), `DE_PLZ`,
  `DE_SOCIAL_SECURITY` (checksum), `DE_VAT_ID` (checksum), `DE_FUEHRERSCHEIN`, `DE_KFZ`,
  `DE_TAX_NUMBER`, `DE_HANDELSREGISTER`
- `in`: `IN_AADHAAR` (Verhoeff), `IN_PAN`, `IN_GSTIN` (structure), `IN_PASSPORT`, `IN_VOTER`, `IN_VEHICLE_REGISTRATION`
- `it`: `IT_FISCAL_CODE` (checksum), `IT_VAT_CODE` (checksum), `IT_DRIVER_LICENSE`, `IT_IDENTITY_CARD`, `IT_PASSPORT`
- `es`: `ES_NIF` (mod-23), `ES_NIE` (mod-23), `ES_PASSPORT`

By default all enabled entities are detected; pass `Entities` to restrict. Entity types and country
codes are open string vocabularies (custom recognizers can add their own), so the API takes `string`;
the `PiiEntities` and `PiiCountries` constant classes provide discoverability and typo-safety:

```csharp
builder.RedactPii(new PiiOptions
{
    Entities  = [PiiEntities.EmailAddress, PiiEntities.PhoneNumber, PiiEntities.UsSsn],
    Countries = [PiiCountries.Uk, PiiCountries.De],
});
```

Anonymization operators: `replace` (default, `<ENTITY_TYPE>`), `redact`, `mask`, `hash`,
`encrypt`/`decrypt` (reversible AES), `keep`, `custom`. Configure per-entity via `Operators`.

| `PiiOptions` | Type | Default |
|--------|------|---------|
| Entities | `IReadOnlyList<string>?` | null (all entities) |
| Countries | `IReadOnlyList<string>?` | null (generic + US only) |
| Operators | `IReadOnlyDictionary<string, OperatorConfig>?` | null (replace with `<ENTITY_TYPE>`) |
| Replacement | `string?` | null (flat replacement, e.g. `[REDACTED]`) |
| Language | `string` | `en` |
| ScoreThreshold | `double` | 0.4 |
| ContextMatchingMode | `Substring` / `WholeWord` | `Substring` |
| AllowList | `IReadOnlyList<string>?` | null |
| RedactOutput | `bool` | true (Both phase; false = Input only) |

`ContextMatchingMode` controls how a recognizer's context words are matched against the
(stemmed) tokens around a candidate: `Substring` (default) matches `card` inside `creditcard`;
`WholeWord` requires an exact token match, reducing false context hits.

```csharp
// enable UK + German packs on top of the generic + US defaults
builder.RedactPii(new PiiOptions { Countries = ["uk", "de"] });
```

### Reversible de-identification, structured data, and batch (engine APIs)

Beyond the `PiiRule` pipeline rule, `AgentGuard.Pii` exposes its engines directly for richer
workflows. All are fully offline.

The quickest entry point is the `PiiEngine` facade, configured once from the same `PiiOptions` as the
rule, with one-liners for every operation:

```csharp
var pii = new PiiEngine(new PiiOptions { Countries = ["de"] });   // or PiiEngine.Create("en", "de")

pii.Anonymize(text).Text;                       // free-text redaction
var deid = pii.Deidentify(text);                // PiiDeidentificationResult (persist deid.Items)
pii.Reidentify(deid, reverseOps).Text;          // restore (decrypt)
pii.AnonymizeJson(json, scope);                 // structured JSON
pii.AnonymizeCsv(header, rows);                 // structured CSV
pii.AnonymizeBatch(records);                    // batch over keyed records
```

The lower-level engines below are also available directly when you need full control.

**Reversible de-identification** - encrypt PII spans, persist the items, restore later:

```csharp
var analyzer   = new AnalyzerEngine(PiiRecognizers.CreateDefaultRegistry("en"));
var anonymizer = new AnonymizerEngine();
var encryptOps = new Dictionary<string, OperatorConfig>
{
    ["DEFAULT"] = new("encrypt", new Dictionary<string, object> { ["key"] = "0123456789abcdef" }),
};

var encrypted = anonymizer.Anonymize(text, analyzer.Analyze(text, "en"), encryptOps);
var deid      = PiiDeidentificationResult.FromEngineResult(encrypted); // .IsReversible

// later, with the same key:
var decryptOps = new Dictionary<string, OperatorConfig>
{
    ["DEFAULT"] = new("decrypt", new Dictionary<string, object> { ["key"] = "0123456789abcdef" }),
};
var restored = new DeanonymizerEngine().Deanonymize(deid.AnonymizedText, deid.Items, decryptOps);
// restored.Text == text (byte-for-byte)
```

`DeanonymizerEngine` reverses `encrypt` (default `decrypt`) and `custom` spans. Lossy operators
(`replace`/`redact`/`mask`/`hash`/`keep`) are reported as non-reversible (`IsReversible == false`,
and `Deanonymize` throws if asked to `decrypt` them); a wrong or missing key throws clearly.

**Structured data** - redact JSON by key path or CSV by inferred column:

```csharp
var structured = new StructuredEngine(analyzer);

// JSON: allowlist only $.user.email; structure and non-string types preserved
var redactedJson = structured.AnonymizeJson(
    json, new JsonRedactionScope { IncludePaths = ["user.email"] });

// CSV/TSV: per-column inference; benign columns are left untouched
var result = structured.AnonymizeCsv(header, rows);   // result.ColumnEntities reports PII columns
```

**Batch** - analyze/anonymize lists or keyed records, results aligned to input:

```csharp
var batchAnalyzer   = new BatchAnalyzerEngine(analyzer);
var batchAnonymizer = new BatchAnonymizerEngine();

var detections = batchAnalyzer.Analyze(records);                  // IReadOnlyDictionary<string,string>
var anonymized = batchAnonymizer.Anonymize(records, detections);  // keys preserved
```

See [`samples/PiiShowcase`](../samples/PiiShowcase) for a runnable end-to-end tour.

### Named-entity recognition (ONNX, offline, multilingual)

`.RedactPiiWithNer(nerOptions, piiOptions?)` or
`.RedactPiiWithNer(modelPath, tokenizerPath, configPath, threshold, piiOptions?)` (from `AgentGuard.Onnx`)

Order 20, same `PiiRule` pass. Augments the regex/checksum recognizers with an offline ONNX
named-entity recognizer that detects the span entity types regex cannot catch - **`PERSON`,
`LOCATION`, `ORGANIZATION`, `DATE_TIME`** - and resolves them against the regex entities in a single
analyzer -> anonymizer pass (so overlap resolution and anonymization treat them uniformly). The NER
spans flow through the same engine, so the redaction output mixes `<PERSON>`, `<LOCATION>`,
`<EMAIL_ADDRESS>`, etc. transparently.

Uses a [GLiNER](https://huggingface.co/urchade/gliner_multi_pii-v1) span model (mDeBERTa-v3-base
backbone, Apache-2.0) - **multilingual** (the reason to add it; regex and spaCy-style NER are
English-leaning) and zero-shot. The model is **not bundled**; download it separately via
[`eng/download-gliner-model.sh`](../eng/download-gliner-model.sh). Not part of `UseDefaults()`.

`GlinerNerOptions.NerThreshold` (default **0.5**, the micro-F1 optimum - see
[`eng/gliner-eval/RESULTS.md`](../eng/gliner-eval/RESULTS.md)) is the binding gate for NER spans; the
analyzer's `PiiOptions.ScoreThreshold` still applies on top. NER coverage targets whitespace-segmented
scripts (Latin / Cyrillic / Arabic / Devanagari); CJK is out of practical scope for the word splitter.

| `GlinerNerOptions` | Type | Default |
|--------|------|---------|
| ModelPath | `string` | *(required)* |
| TokenizerPath | `string` | *(required)* mDeBERTa-v3 `spm.model` |
| ConfigPath | `string` | *(required)* `config.json` (special-token ids + max span width) |
| NerThreshold | `float` | 0.5 |
| MaxSpanWidth | `int` | 12 |
| EntityLabelMap | `IReadOnlyDictionary<string,string>` | `person→PERSON`, `location→LOCATION`, `organization→ORGANIZATION`, `date→DATE_TIME` |

```csharp
// detect names/places/orgs/dates alongside regex PII, in one order-20 pass
builder.RedactPiiWithNer(
    modelPath: "models/gliner/model.onnx",
    tokenizerPath: "models/gliner/spm.model",
    configPath: "models/gliner/config.json",
    piiOptions: new PiiOptions { Countries = ["de"] });
```

## PII Detection (LLM)

`.DetectPIIWithLlm(chatClient, options?)`

Order 25, Both phases. Catches unstructured PII (names, addresses, contextual identifiers) that regex misses.

| Option | Type | Default |
|--------|------|---------|
| Action | `PiiAction` | Block |
| SystemPrompt | `string?` | null (built-in templates) |

`PiiAction.Block` returns a blocked result. `PiiAction.Redact` returns a modified result with the LLM's redacted version.

## Topic Boundary Enforcement (LLM)

`.EnforceTopicBoundaryWithLlm(chatClient, topics...)`

Order 35, Input phase. Semantic topic classification using an LLM that understands intent and conversation context. Conversation history is included in the prompt so short follow-up replies ("yes", "tell me more") are correctly classified based on the preceding conversation.

| Option | Type | Default |
|--------|------|---------|
| AllowedTopics | `IList<string>` | [] |
| SystemPrompt | `string?` | null (built-in template with `{topics}` and `{history}` placeholders) |

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

## Content Safety (ONNX - Opir, offline multilingual)

`.BlockUnsafeContentWithOpir(options)` or `.BlockUnsafeContentWithOpir(modelPath, tokenizerPath, prefixPath, threshold)`

Order 50, Input phase. Requires `AgentGuard.Onnx`. Uses the [Opir-multilang](https://huggingface.co/knowledgator/opir-multitask-multilang-v1.0) model (GLiClass uni-encoder over mDeBERTa-v3-base, Apache-2.0) to score text against a frozen harm taxonomy - **toxicity, hate speech, violence, sexual content, self-harm, harassment** - in any language. Blocks when the strongest per-label probability reaches the threshold. Fully offline.

This is an **offline, multilingual** content-safety guard - the gap the other classifiers leave open. The bundled Defender is English-only (~0% recall off-English), and cloud content-safety APIs are per-call and PII-bound. Opir-multilang gives genuine non-English coverage locally (≈40-76% recall at 16-36% FPR across de/es/ru/ar/zh/hi on `textdetox/multilingual_toxicity_dataset`). Position it as *complementing* (not replacing) Azure Content Safety, the way Defender is positioned for English injection. See [`eng/opir-eval/RESULTS.md`](../eng/opir-eval/RESULTS.md) for the full benchmark.

**Setup:** Download the model from HuggingFace using the included script:
```bash
./eng/download-opir-model.sh
# Downloads model.onnx (fp16 ~561MB) + spm.model + prefix.json to ./models/opir-multilang/
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| ModelPath | `string` | *(required)* | Path to the Opir-multilang ONNX model file |
| TokenizerPath | `string` | *(required)* | Path to the mDeBERTa-v3 SentencePiece model (spm.model) |
| PrefixPath | `string` | *(required)* | Path to the frozen-taxonomy label prefix (prefix.json) |
| Threshold | `float` | 0.5 | Block threshold on the max per-label probability. Tunable per deployment (FPR is somewhat threshold-sensitive here) |
| MaxTokenLength | `int` | 512 | Maximum input token length (truncated if longer) |
| IncludeConfidence | `bool` | true | Include the triggering label, score, and full per-label scores in result metadata |

When blocked, result metadata includes:
- `label` - the harm category with the highest score (e.g. "hate speech")
- `confidence` - that label's probability (0.0-1.0)
- `scores` - per-harm-label probabilities
- `model` - `opir-multilang-mdeberta-v3`
- `threshold` - the configured threshold

> The model is a frozen-taxonomy ONNX export distributed at [`filip-w/opir-multilang-onnx`](https://huggingface.co/filip-w/opir-multilang-onnx). The graph also bakes a `safe and benign` sentinel label (excluded from the block decision) that GLiClass needs for calibration.

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

**MAF integration (`UseAgentGuard()`):** When this rule is in the policy, tool results are automatically intercepted via the MAF function-invocation middleware (requires `FunctionInvokingChatClient` in the inner agent). Each `FunctionResultContent` is evaluated BEFORE being fed back to the LLM. Blocked results are replaced with a placeholder; sanitized results substitute the modified content. As a safety net for tools that bypass `FunctionInvokingChatClient` (hosted tools, MCP), the post-hoc output guardrail also extracts `FunctionResultContent` from the response messages. Configure via `ToolResultMiddlewareOptions` on the `UseAgentGuard(policy, toolResultOptions, logger)` overload (`Enabled`, `IncludeRuleOrders`, `BlockedPlaceholder`, `HardFail`).

**Manual usage:** Place tool results in `GuardrailContext.Properties["ToolResults"]` as `IReadOnlyList<ToolResultEntry>`. When action is Sanitize, sanitized results are written to `Properties["SanitizedToolResults"]`. Violations are stored in `Properties["ToolResultViolations"]`.

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
var guarded = executor.WithGuardrails(b => b.BlockPromptInjection().RedactPii());

// Pre-built policy overload
var guarded = executor.WithGuardrails(existingPolicy);

// With options (custom text extractor, logger)
var guarded = executor.WithGuardrails(b => b.RedactPii(),
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

## Dynamic rule enabling

`.When(predicate)` / `.Unless(predicate)`

Gate the **most recently added** rule behind a runtime predicate, evaluated per request. When the predicate returns false (`.When`) or true (`.Unless`), the rule is skipped and passes through; `Name`, `Phase` and `Order` are preserved so execution order and telemetry are unchanged. Both sync (`Func<GuardrailContext, bool>`) and async (`Func<GuardrailContext, CancellationToken, ValueTask<bool>>`) predicates are supported. Internally this wraps the rule in a `ConditionalGuardrailRule`, which you can also construct directly and pass to `.AddRule(...)`.

The predicate can read the `GuardrailContext` (`Properties`, `AgentName`, `Messages`) and/or capture ambient services in its closure.

**Recommended for the Defender [English-centric limitation](#prompt-injection-detection-onnx---stackone-defender): raise the threshold per-segment rather than disabling.** Add two gated Defender rules (both order 11; only one fires per request) - a sensitive instance for English users and a conservative one for everyone else. Non-English benign text passes the higher bar while high-confidence, language-agnostic attacks still block:

```csharp
var policy = new GuardrailPolicyBuilder()
    .BlockPromptInjectionWithDefender()                  // default threshold for English users
        .When(ctx => IsEnglish(ctx))
    .BlockPromptInjectionWithDefender(new DefenderPromptInjectionOptions { MainThreshold = 0.9f })
        .Unless(ctx => IsEnglish(ctx))                   // conservative for everyone else
    .Build();
```

**Gate by a value set on the context** (standalone pipeline - the caller populates `Properties`):

```csharp
bool IsEnglish(GuardrailContext ctx) =>
    !ctx.Properties.TryGetValue("language", out var l) || (string)l == "en";

// caller sets the per-request language
var ctx = new GuardrailContext
{
    Text = userInput,
    Phase = GuardrailPhase.Input,
    Properties = { ["language"] = userProfile.Language }
};
```

**Gate by HttpContext / ClaimsPrincipal** (ASP.NET - the predicate closure captures `IHttpContextAccessor`; it flows correctly because the pipeline runs on the request's async context, so no extra plumbing is needed):

```csharp
// httpContextAccessor is resolved from DI (AddHttpContextAccessor())
bool IsEnglish(GuardrailContext _)
{
    var user = httpContextAccessor.HttpContext?.User;
    var lang = user?.FindFirst("locale")?.Value
        ?? httpContextAccessor.HttpContext?.Features
            .Get<IRequestCultureFeature>()?.RequestCulture.Culture.TwoLetterISOLanguageName;
    return lang is null or "en";
}
```

The full enable/disable form (`.Unless(predicate)` to skip a rule entirely) is still available and gates any rule on any ambient signal - feature flags, tenant tier, A/B cohort, user role, etc. Prefer raising a threshold over fully disabling a security rule whenever a tuned threshold exists.

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
