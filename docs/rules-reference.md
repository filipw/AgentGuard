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
| DecodeLeetspeak | `bool` | true | Decode leetspeak substitutions |
| StripInvisibleUnicode | `bool` | true | Strip zero-width and other invisible characters, including Unicode tag characters (U+E0000-U+E007F, "ASCII smuggling"); text spelled in tag characters is also surfaced as a decoded view |
| MinBase64Length | `int` | 16 | Minimum base64 segment length to attempt decoding |

`NormalizeUnicode` and `StripInvisibleUnicode` rewrite the text itself. The decoders append what they decode after a `[DECODED]` marker, so downstream rules can evaluate both the text and its decoded forms.

## Retrieval Guardrails (RAG)

`.GuardRetrieval(options?)`

Order 8, Input phase. Filters retrieved chunks before they reach the LLM context. Place the chunks in `GuardrailContext.Properties["RetrievalChunks"]` as `IReadOnlyList<RetrievedChunk>`; the rule writes the surviving chunks to `Properties["ApprovedChunks"]` and the per-chunk evaluation to `Properties["RetrievalGuardrailResult"]`, and leaves the user's text unchanged. `EvaluateChunks(chunks)` runs the same checks outside a pipeline, and `RetrievalGuardrailContextProvider` (`AgentGuard.AgentFramework`) plugs it into a MAF agent as a context provider.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| DetectPromptInjection | `bool` | true | Flag chunks carrying injection patterns (instruction overrides, persona directives, chat-template tokens, instructions in HTML comments, "open this URL" directives) |
| DetectSecrets | `bool` | true | Flag chunks carrying AWS access keys, GitHub tokens, PEM private keys, API key assignments or JWTs |
| DetectPII | `bool` | false | Flag chunks carrying email addresses, US phone numbers or SSN-shaped numbers |
| MinRelevanceScore | `double?` | null | Drop chunks whose `Score` is below this; chunks without a score are kept |
| MaxChunks | `int?` | null | Keep only this many chunks, highest score first |
| Action | `RetrievalFilterAction` | Remove | `Remove` drops a flagged chunk; `Sanitize` keeps it with each finding replaced |
| CustomFilters | `IList<(string Name, Func<string, bool> Predicate)>` | [] | Extra checks on the chunk text; when sanitizing, a chunk a custom filter flags is replaced entirely |
| SanitizationReplacement | `string` | `[FILTERED]` | Replacement text when sanitizing |

With `Sanitize`, every filter a chunk trips is applied. A PEM private key is replaced as a whole block - from its `-----BEGIN ... PRIVATE KEY-----` line (RSA, EC, DSA, OPENSSH, ENCRYPTED, PKCS#8 or PGP) through the matching `-----END ...-----` line, or to the end of the chunk when that line is missing. Chunks dropped by `MinRelevanceScore` or `MaxChunks` are removed whatever the `Action`. When chunks are removed, the result carries `filteredCount`, `totalChunks` and `approvedCount` metadata.

## Prompt Injection Detection (Regex)

`.BlockPromptInjection(sensitivity)`

Order 10, Input phase. Patterns informed by the [Arcanum Prompt Injection Taxonomy](https://github.com/Arcanum-Sec/arc_pi_taxonomy). The builder method sets `Sensitivity`; for the other options add the rule directly: `.AddRule(new PromptInjectionRule(new PromptInjectionOptions { ... }))`.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| Sensitivity | `Sensitivity` | Medium | Low / Medium / High |
| CustomPatterns | `IList<string>` | [] | Additional regex patterns; an invalid one throws when the rule is constructed |
| BlockSystemPromptExtraction | `bool` | true | Run the system prompt extraction patterns |
| BlockRolePlayAttacks | `bool` | true | Run the role/persona hijacking patterns |
| MatchTimeout | `TimeSpan` | 250 ms | Budget per pattern evaluation |
| OnError | `ErrorBehavior` | FailOpen | Outcome when a pattern timed out and no other pattern matched |

A pattern that exceeds `MatchTimeout` does not end the scan: the remaining patterns still run and any match blocks. The built-in patterns run in time linear in the input.

**Sensitivity tiers:**

| Tier | Detects |
|------|---------|
| Low (Core) | Direct instruction override, role/persona hijacking (including "developer mode"), security bypass requests, forged assistant turns and chat-role markers followed by a directive, end sequence injection (chat-template tokens, fake role tags, bracketed frames, separator lines), instructions in HTML comments, variable expansion |
| Medium (+Medium) | + System prompt extraction, jailbreak keywords, rule addition/modification, anti-harm coercion, contradiction ("your real instructions are...") |
| High (+High) | + Framing attacks (hypothetical/fictional contexts), inversion/double-negative extraction, link injection, bare chat-role markers (`System:`, `User:` at the start of a line) |

## Prompt Injection Detection (ONNX - StackOne Defender)

`.BlockPromptInjectionWithDefender()`, `.BlockPromptInjectionWithDefender(mainThreshold)` or `.BlockPromptInjectionWithDefender(options)`

Order 11, Input phase. Uses the [StackOne Defender](https://github.com/StackOneHQ/defender) fine-tuned multi-head MiniLM-L6 ONNX model (minilm-multihead-v5, ~22 MB, int8 quantized). Fast (~8 ms), fully offline, **bundled** - the model ships in the [Kyoto](https://github.com/filipw/kyoto) package that `AgentGuard.Onnx` depends on and is copied next to your app on build, so no separate download is required.

The model emits two temperature-calibrated scores: a **main** injection score and an **aux** "directed at a human reader" score. Input is blocked when `main >= MainThreshold AND aux < AuxThreshold` - a high aux score **vetoes** the block. This rescues imperative-but-benign phrasings (e.g. "show me my orders", "list all my orders") that score high on the main head.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| MainThreshold | `float` | 0.75 | Main-head block threshold (0.0–1.0) |
| AuxThreshold | `float` | 0.64 | Aux-head veto threshold (0.0–1.0); aux at or above this rescues the block |
| TemperatureT | `float` | 2.41 | Calibration temperature; each logit is divided by this before sigmoid |
| MaxTokenLength | `int` | 256 | Model input size; longer input is split into windows, not truncated |
| WindowSize | `int` | 64 | Tokens per window when the input doesn't fit in one; small windows keep a short injection from being diluted by surrounding text |
| WindowOverlap | `int` | 32 | Tokens shared by consecutive windows, so nothing that short is cut in half |
| MaxWindows | `int` | 512 | Input needing more windows is blocked (Medium severity, `inputTooLong` metadata) without running the model; 0 = no limit |
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

**Long input.** Text that fits in one window is classified in a single call. Longer text is split into overlapping windows that cover all of it; the rule blocks if any window blocks, and the metadata of the worst window adds `windowIndex`, `windowCount`, `windowStart` and `windowLength`. Cost grows with length (about 5 ms per window on a laptop CPU). Because every passage is classified, long technical or instructional text (man pages, READMEs) is blocked more often than short prompts - raise `WindowSize` (up to `MaxTokenLength - 2`) to trade dilution resistance for fewer such blocks.

**Limitations.**

- **English-centric.** Trained mostly on English, the model over-fires on non-English benign input (e.g. ordinary German questions). For non-English users, raise `MainThreshold` for that segment rather than disabling the rule (see [Dynamic rule enabling](#dynamic-rule-enabling)). Tradeoff: a higher threshold also weakens detection of *native-language* attacks, so pair it with a multilingual classifier for real coverage.
- **Residual English imperatives.** A few "show me X" phrasings (e.g. "show me my account details") still block - confidently misscored ~90% with low aux, so no threshold short of ~0.9-0.93 rescues them, and that costs recall.

The default `MainThreshold` is **0.75** (within the F1-optimal plateau on a held-out jailbreak set: ~4× lower false-positive rate than 0.5 for a few points of recall). Raise toward 0.9/0.93 to cut false positives further at a recall cost.

## Prompt Injection Detection (ONNX - DeBERTa v3)

`.BlockPromptInjectionWithDeberta(options)` or `.BlockPromptInjectionWithDeberta(modelPath, tokenizerPath, threshold)`

Order 12, Input phase. Uses a fine-tuned DeBERTa v3 ONNX model (`protectai/deberta-v3-base-prompt-injection-v2`) for ML-based binary classification. Fully offline, ~100ms inference. Requires separate model download. For most use cases, prefer the Defender model above.

**Setup:** AgentGuard ships no model for this rule. Download `model.onnx` (~370 MB) and `spm.model` from the `onnx/` folder of [`protectai/deberta-v3-base-prompt-injection-v2`](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2), or fetch them with the Kyoto bootstrap (see [`eng/MODELS.md`](../eng/MODELS.md)):
```bash
# from a sibling checkout of the Kyoto repo
cd ../kyoto
./bootstrap-models.sh deberta   # model.onnx + spm.model -> ./models/deberta-v3-prompt-injection/
source ./models/env.sh          # exports AGENTGUARD_ONNX_MODEL_PATH and AGENTGUARD_ONNX_TOKENIZER_PATH
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| ModelPath | `string` | *(required)* | Path to the ONNX model file |
| TokenizerPath | `string` | *(required)* | Path to the SentencePiece model file (spm.model) |
| Threshold | `float` | 0.5 | Confidence threshold (0.0–1.0) for injection classification |
| MaxTokenLength | `int` | 512 | Model input size; longer input is split into windows, not truncated |
| WindowSize / WindowOverlap / MaxWindows | `int` | 510 / 128 / 32 | Window size (clamped to what the model accepts), overlap, and the cap above which input is blocked; see the Defender section |
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

Order 12, Input phase. Uses the [PIGuard](https://huggingface.co/leolee99/PIGuard) DeBERTa v3 model (ACL 2025, MIT), trained with the "Mitigating Over-defense for Free" strategy. In AgentGuard's own measurements it keeps benign false positives low (over-defense comparable to the bundled Defender) while detecting **indirect / code-style injection far better** than Defender (BIPIA_code recall 96% vs 34%). Fully offline. A heavier model than Defender, so best used as a standalone guard or layered after it. See the PIGuard evaluation in the [Kyoto](https://github.com/filipw/kyoto) repo for the full benchmark.

**Setup:** Download `model_fp16.onnx` (~369 MB; the fp32 `model.onnx` is also published) and `spm.model` from [`filip-w/PIGuard-onnx`](https://huggingface.co/filip-w/PIGuard-onnx), or fetch them with the Kyoto bootstrap (see [`eng/MODELS.md`](../eng/MODELS.md)):
```bash
# from a sibling checkout of the Kyoto repo
cd ../kyoto
./bootstrap-models.sh piguard   # fp16 model (saved as model.onnx) + spm.model -> ./models/piguard/
source ./models/env.sh          # exports AGENTGUARD_PIGUARD_ONNX_MODEL_PATH and AGENTGUARD_PIGUARD_TOKENIZER_PATH
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| ModelPath | `string` | *(required)* | Path to the PIGuard ONNX model file |
| TokenizerPath | `string` | *(required)* | Path to the DeBERTa v3 SentencePiece model (spm.model) |
| Threshold | `float` | 0.9 | Confidence threshold. The argmax default (0.5) over-blocks; 0.9 is the measured operating point |
| MaxTokenLength | `int` | 512 | Model input size; longer input is split into windows, not truncated |
| WindowSize / WindowOverlap / MaxWindows | `int` | 510 / 128 / 32 | Window size (clamped to what the model accepts), overlap, and the cap above which input is blocked; see the Defender section |
| IncludeConfidence | `bool` | true | Include confidence score in result metadata |

> The model is an ONNX export distributed at [`filip-w/PIGuard-onnx`](https://huggingface.co/filip-w/PIGuard-onnx).

## Prompt Injection Detection (Remote ML)

`.BlockPromptInjectionWithRemoteClassifier(endpointUrl, apiKey?, modelName?, threshold?)`, `.BlockPromptInjectionWithRemoteClassifier(httpClient, classifierOptions, ruleOptions?)` or `.BlockPromptInjectionWithRemoteClassifier(classifier, options?)`

Order 13, Input phase. Calls an external model server for ML-based classification. Designed for SOTA models like [Sentinel-v2](https://huggingface.co/rogue-security/prompt-injection-jailbreak-sentinel-v2) (Qwen3-0.6B, F1 ~0.957, 32K context). Requires `AgentGuard.RemoteClassifier` package.

`EndpointUrl`, `ApiKey`, `ModelName` and `RequestFormat` are `HttpClassifierOptions` (the HTTP client); the rest are `RemotePromptInjectionOptions` (the rule).

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| EndpointUrl | `string` | *(required)* | URL of the classification endpoint |
| ApiKey | `string?` | null | Sent as a Bearer token in the `Authorization` header of each request; it is never set on the `HttpClient`, so classifiers sharing a client each send their own key |
| ModelName | `string?` | null | Model name for result metadata |
| RequestFormat | `HttpClassifierRequestFormat` | HuggingFace | Request/response format (HuggingFace or Simple) |
| InjectionLabels | `ISet<string>` | jailbreak, injection, malicious, unsafe, INJECTION | Labels indicating injection (case-insensitive) |
| Threshold | `float` | 0.5 | Confidence threshold (0.0–1.0) |
| IncludeConfidence | `bool` | true | Include the score in result metadata |
| OnError | `ErrorBehavior` | FailOpen | What to do on error: FailOpen (pass), Warn (pass + metadata), FailClosed (block) |
| Timeout | `TimeSpan` | 10s | HTTP request timeout |

When blocked, result metadata includes:
- `label` - the predicted label (e.g. "jailbreak")
- `confidence` - classification score (0.0–1.0)
- `model` - model name (if configured)
- `threshold` - the configured threshold

**Setting up a Sentinel-v2 endpoint:** any small HTTP app wrapping `transformers.pipeline("text-classification", ...)` (for example FastAPI + uvicorn) works. The classifier sends `POST {EndpointUrl}` with `{"inputs": "<text>"}` (`HuggingFace`, the default) or `{"text": "<text>"}` (`Simple`), and reads the pipeline's output - `[{"label": "jailbreak", "score": 0.99}]`, a nested `[[...]]` or a single object - using the first entry.

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

`.RedactPii(options?, ruleOptions?)` or `.RedactPii(replacement, entities...)` (from `AgentGuard.Pii`)

Order 20, Both phases. Offline PII detection and anonymization using validated regex recognizers
with confidence scoring, overlap resolution, lemma-aware context score boosting, and configurable
anonymization operators. `PiiRule` is a thin adapter over the [TasmanianDevil](https://github.com/filipw/tasmaniandevil)
engine, whose types (`PiiOptions`, `PiiEntities`, `PiiCountries`, the engines below) live in the
`TasmanianDevil` namespaces. The engine is inspired by the architecture of Microsoft Presidio; its
attributions are in the `THIRD_PARTY_NOTICES.txt` of the TasmanianDevil package.

**Generic entities (always on):** `CREDIT_CARD` (Luhn), `EMAIL_ADDRESS`, `IBAN_CODE` (mod-97),
`CRYPTO` (Bitcoin checksum), `IP_ADDRESS`, `URL`, `MAC_ADDRESS`, `PHONE_NUMBER` (libphonenumber).

**US pack (always on):** `US_SSN`, `US_ITIN`, `ABA_ROUTING_NUMBER` (checksum), `US_BANK_NUMBER`,
`US_DRIVER_LICENSE`, `US_PASSPORT`, `US_NPI` (Luhn), `US_MBI`, `MEDICAL_LICENSE` (DEA checksum).

**Country packs (opt-in via `Countries`):** enabling every national identifier at once inflates
false positives, so non-US packs are opt-in by ISO 3166-1 alpha-2 code:

- `uk` (`gb` is accepted as an alias): `UK_NINO`, `UK_NHS` (mod-11), `UK_POSTCODE`, `UK_PASSPORT`, `UK_DRIVING_LICENCE`, `UK_VEHICLE_REGISTRATION`
- `de`: `DE_ID_DOCUMENT` (ICAO checksum; the Personalausweis and Reisepass share one format and
  cannot be told apart by the number alone, so they are a single entity type), `DE_TAX_ID` (checksum), `DE_PLZ`,
  `DE_SOCIAL_SECURITY` (checksum), `DE_VAT_ID` (checksum), `DE_FUEHRERSCHEIN`, `DE_KFZ`,
  `DE_TAX_NUMBER`, `DE_HANDELSREGISTER`
- `in`: `IN_AADHAAR` (Verhoeff), `IN_PAN`, `IN_GSTIN` (structure), `IN_PASSPORT`, `IN_VOTER`, `IN_VEHICLE_REGISTRATION`
- `it`: `IT_FISCAL_CODE` (checksum), `IT_VAT_CODE` (checksum), `IT_DRIVER_LICENSE`, `IT_IDENTITY_CARD`, `IT_PASSPORT`
- `es`: `ES_NIF` (mod-23), `ES_NIE` (mod-23), `ES_PASSPORT`
- `nl`: `NL_BSN` (11-proef), `NL_POSTCODE`, `NL_PASSPORT` - each needs a nearby context word (`bsn`,
  `postcode`, `paspoort`, ...) to clear the default threshold

By default all enabled entities are detected; pass `Entities` to restrict. Entity types and country
codes are open string vocabularies (custom recognizers can add their own), so the API takes `string`;
the `PiiEntities` and `PiiCountries` constant classes provide discoverability and typo-safety:

```csharp
using AgentGuard.Pii;      // RedactPii()
using TasmanianDevil;      // PiiOptions, PiiEntities, PiiCountries

builder.RedactPii(new PiiOptions
{
    Entities  = [PiiEntities.EmailAddress, PiiEntities.PhoneNumber, PiiEntities.UsSsn],
    Countries = [PiiCountries.Uk, PiiCountries.De],
});
```

Anonymization operators: `replace` (default, `<ENTITY_TYPE>`), `redact`, `mask`, `hash`,
`encrypt`/`decrypt` (reversible, authenticated AES-GCM), `keep`, `custom`. Configure per-entity via `Operators`.

| `PiiOptions` | Type | Default |
|--------|------|---------|
| Entities | `IReadOnlyList<string>?` | null (all entities) |
| Countries | `IReadOnlyList<string>?` | null (generic + US only) |
| Operators | `IReadOnlyDictionary<string, OperatorConfig>?` | null (replace with `<ENTITY_TYPE>`) |
| Replacement | `string?` | null (flat replacement for every entity, e.g. `[REDACTED]`; ignored when `Operators` is set) |
| Language | `string` | `en` |
| ScoreThreshold | `double` | 0.4 |
| ContextMatchingMode | `Substring` / `WholeWord` | `Substring` |
| AllowList | `IReadOnlyList<string>?` | null |
| AllowListMatch | `Exact` / `Regex` | `Exact` (`Regex` treats each entry as a pattern) |
| ConflictResolution | `MergeSimilarOrContained` / `RemoveIntersections` | `MergeSimilarOrContained` (`RemoveIntersections` also trims partially overlapping spans) |
| MergeEntitiesWithSpaces | `bool` | true (adjacent same-type spans separated only by spaces become one entity; false anonymizes each span on its own) |

`ContextMatchingMode` controls how a recognizer's context words are matched against the
(stemmed) tokens around a candidate: `Substring` (default) matches `card` inside `creditcard`;
`WholeWord` requires an exact token match, reducing false context hits.

Guardrail-side settings live on AgentGuard's `PiiRuleOptions`, passed as the second argument
(`.RedactPii(options, ruleOptions)`; `RedactPiiWithNer` takes it too): `RedactOutput` (default `true`)
runs the rule on input and output, `false` on input only.

```csharp
// enable UK + German packs on top of the generic + US defaults
builder.RedactPii(new PiiOptions { Countries = ["uk", "de"] });

// redact user input only, leave model output alone
builder.RedactPii(new PiiOptions(), new PiiRuleOptions { RedactOutput = false });
```

### Reversible de-identification, structured data, and batch (engine APIs)

Beyond the `PiiRule` pipeline rule, the TasmanianDevil engine behind it can be used directly for
richer workflows. All are fully offline. `PiiEngine`, `PiiOptions` and `PiiRecognizers` are in the
`TasmanianDevil` namespace; the lower-level engines are in `TasmanianDevil.Analyzer`,
`TasmanianDevil.Anonymizer` (with `OperatorConfig` in `TasmanianDevil.Anonymizer.Operators`),
`TasmanianDevil.Structured` and `TasmanianDevil.Batch`.

The quickest entry point is the `PiiEngine` facade, configured once from the same `PiiOptions` as the
rule, with one-liners for every operation:

```csharp
using TasmanianDevil;

var pii = new PiiEngine(new PiiOptions { Countries = ["de"] });   // or PiiEngine.Create("en", "de")

pii.Anonymize(text).Text;                       // free-text redaction
var deid = pii.Deidentify(text);                // PiiDeidentificationResult (persist deid.Items)
pii.Reidentify(deid, reverseOps).Text;          // restore spans anonymized with encrypt (decrypt)
pii.AnonymizeJson(json, scope);                 // structured JSON
pii.AnonymizeCsv(header, rows);                 // structured CSV
pii.AnonymizeBatch(records);                    // batch over keyed records
```

`AnalyzeAsync`, `AnonymizeAsync` and `DeidentifyAsync` also run asynchronous recognizers - such as the
remote and Azure detectors in [Remote PII detection](remote-pii.md), passed through the constructor's
`extraRecognizers` - which the synchronous methods skip. The lower-level engines below are available
directly when you need full control.

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

// JSON: analyze only values under the user.email path; structure and non-string types preserved
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

See [`samples/AgentFrameworkPii`](../samples/AgentFrameworkPii) for a runnable tour of PII in an agent, and [`samples/RemotePii`](../samples/RemotePii) for out-of-process detection.

### Named-entity recognition (ONNX, offline, multilingual)

`.RedactPiiWithNer(nerOptions, piiOptions?, ruleOptions?)` or
`.RedactPiiWithNer(modelPath, tokenizerPath, configPath, threshold?, piiOptions?, ruleOptions?)` (from `AgentGuard.Onnx`)

Order 20, same `PiiRule` pass. Augments the regex/checksum recognizers with an offline ONNX
named-entity recognizer that detects the span entity types regex cannot catch - **`PERSON`,
`LOCATION`, `ORGANIZATION`, `DATE_TIME`** - and resolves them against the regex entities in a single
analyzer -> anonymizer pass (so overlap resolution and anonymization treat them uniformly). The NER
spans flow through the same engine, so the redaction output mixes `<PERSON>`, `<LOCATION>`,
`<EMAIL_ADDRESS>`, etc. transparently.

Uses a [GLiNER](https://huggingface.co/urchade/gliner_multi_pii-v1) span model (mDeBERTa-v3-base
backbone, Apache-2.0) - **multilingual** (the reason to add it; regex and spaCy-style NER are
English-leaning) and zero-shot. The model is **not bundled**; download it from
[`filip-w/gliner-multi-pii-onnx`](https://huggingface.co/filip-w/gliner-multi-pii-onnx) (model, `spm.model`
and `config.json`) or with the Kyoto bootstrap - see [`eng/MODELS.md`](../eng/MODELS.md). Not part of `UseDefaults()`.

`GlinerNerOptions.NerThreshold` (default **0.5**, the micro-F1 optimum - see
the GLiNER evaluation in the [Kyoto](https://github.com/filipw/kyoto) repo) is the binding gate for NER spans; the
analyzer's `PiiOptions.ScoreThreshold` still applies on top. NER coverage targets whitespace-segmented
scripts (Latin / Cyrillic / Arabic / Devanagari); CJK is out of practical scope for the word splitter.

`GlinerNerOptions` comes from the `TasmanianDevil.Onnx` package (`using TasmanianDevil.Onnx;`), which
`AgentGuard.Onnx` depends on.

| `GlinerNerOptions` | Type | Default |
|--------|------|---------|
| ModelPath | `string` | *(required)* |
| TokenizerPath | `string` | *(required)* mDeBERTa-v3 `spm.model` |
| ConfigPath | `string` | *(required)* `config.json` (special-token ids + max span width) |
| NerThreshold | `float` | 0.5 |
| MaxTokenLength | `int` | 384 (tokens per inference call, label prompt included; longer input is split into chunks) |
| MaxSpanWidth | `int` | 12 (in words; must match the value the ONNX graph was exported with) |
| MaxChunkChars | `int` | 1200 (characters per chunk; chunks hold whole words and their spans are mapped back onto the full text) |
| EntityLabelMap | `IReadOnlyDictionary<string,string>` | `person→PERSON`, `location→LOCATION`, `organization→ORGANIZATION`, `date→DATE_TIME` |

```csharp
using AgentGuard.Onnx;     // RedactPiiWithNer()
using TasmanianDevil;      // PiiOptions

// detect names/places/orgs/dates alongside regex PII, in one order-20 pass
builder.RedactPiiWithNer(
    modelPath: "models/gliner/model.onnx",
    tokenizerPath: "models/gliner/spm.model",
    configPath: "models/gliner/config.json",
    piiOptions: new PiiOptions { Countries = ["de"] });
```

## Secrets Detection

`.DetectSecrets(action?)` or `.DetectSecrets(options)`

Order 22, Both phases. Detects API keys, tokens, connection strings, private keys and other credentials, so they are neither sent to the model nor leaked in its output.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| Categories | `SecretCategory` | Default | Flags: `ApiKey` (API key/token assignments, bearer tokens, Slack tokens), `AwsCredential`, `ConnectionString` (with a password; MongoDB/Redis URIs with credentials), `PrivateKey` (PEM), `JwtToken`, `GitHubToken`, `AzureKey` (storage account and subscription keys). `GenericHighEntropy` is opt-in (`All` includes it) |
| Action | `SecretAction` | Block | `Block` rejects the text; `Redact` replaces each match with `Replacement` |
| Replacement | `string` | `[SECRET_REDACTED]` | Replacement text when redacting, inserted literally |
| CustomPatterns | `IDictionary<string, string>` | {} | Additional patterns: label -> regex |
| MinHighEntropyLength | `int` | 20 | Shortest token `GenericHighEntropy` considers (at least 8); a token is flagged when its Shannon entropy is above 4.5 |

A PEM private key matches as a whole block - from the `-----BEGIN ... PRIVATE KEY-----` line (RSA, EC, DSA, OPENSSH, ENCRYPTED, PKCS#8 or PGP's `PRIVATE KEY BLOCK`) through the matching `-----END ...-----` line, or to the end of the text when that line is missing - so `Redact` removes the key body, not just its header. A bare 40-character AWS secret key or 32-character hex Azure subscription key is only flagged when related context (`aws`, `secret_access_key`, `azure`, `ocp-apim-subscription-key`, ...) appears in the text. When blocked, result metadata includes `detectedCategories` (e.g. `aws-access-key`, `private-key`).

## PII Detection (LLM)

`.DetectPIIWithLlm(chatClient, options?)`

Order 25, Both phases. Catches unstructured PII (names, addresses, contextual identifiers) that regex misses.

| Option | Type | Default |
|--------|------|---------|
| Action | `PiiAction` | Redact |
| SystemPrompt | `string?` | null (built-in templates) |

`PiiAction.Block` returns a blocked result. `PiiAction.Redact` returns a modified result with the LLM's redacted version - everything after the judge's `REDACTED:` marker, across all lines (the marker may also sit on its own line).

## Topic Boundary Enforcement (LLM)

`.EnforceTopicBoundaryWithLlm(chatClient, topics...)` or `.EnforceTopicBoundaryWithLlm(chatClient, options)`

Order 35, Input phase. Semantic topic classification using an LLM that understands intent and conversation context. Conversation history is included in the prompt so short follow-up replies ("yes", "tell me more") are correctly classified based on the preceding conversation.

| Option | Type | Default |
|--------|------|---------|
| AllowedTopics | `IList<string>` | *(required)* |
| SystemPrompt | `string?` | null (built-in template with `{topics}` and `{history}` placeholders) |

## Token Limits

`.LimitInputTokens(max, strategy)` / `.LimitOutputTokens(max, strategy)`

Order 40, Input or Output phase.

Strategies: `Reject`, `Truncate`, `Warn`

Uses `Microsoft.ML.Tokenizers` (cl100k_base) for accurate token counting.

## Content Safety

`.BlockHarmfulContent(maxSeverity)` or `.BlockHarmfulContent(options)` or `.BlockHarmfulContent(classifier, options?)`

Order 50, Both phases.

Requires an `IContentSafetyClassifier`. Use `AgentGuard.Azure` for Azure AI Content Safety integration (see [Azure integration](azure-integration.md)). The first two overloads attach no classifier, so the rule cannot reach a verdict: every evaluation reports a rule error, which the default `OnError` (FailOpen) lets through. Pass the classifier with `.BlockHarmfulContent(classifier, options?)`.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| MaxAllowedSeverity | `ContentSafetySeverity` | Low | Highest severity allowed; anything above it blocks |
| Categories | `ContentSafetyCategory` | All | Which categories to check (Hate, Violence, SelfHarm, Sexual) |
| BlocklistNames | `IList<string>` | [] | Server-side blocklists to check against |
| HaltOnBlocklistHit | `bool` | false | Skip category analysis if blocklist matches (performance optimization) |
| OnError | `ErrorBehavior` | FailOpen | What to do when there is no classifier or the classifier reports a failure: FailOpen (pass), Warn (pass + metadata), FailClosed (block) |

Blocklist matches are checked first and take precedence over category analysis. When a blocklist match is found, the result includes metadata with `blocklistName`, `blocklistItemText`, and `totalMatches`.

## Content Safety (ONNX - Opir, offline multilingual)

`.BlockUnsafeContentWithOpir(options)` or `.BlockUnsafeContentWithOpir(modelPath, tokenizerPath, prefixPath, threshold)`

Order 50, Input phase. Requires `AgentGuard.Onnx`. Uses the [Opir-multilang](https://huggingface.co/knowledgator/opir-multitask-multilang-v1.0) model (GLiClass uni-encoder over mDeBERTa-v3-base, Apache-2.0) to score text against a frozen harm taxonomy - **toxicity, hate speech, violence, sexual content, self-harm, harassment** - in any language. Blocks when the strongest per-label probability reaches the threshold. Fully offline.

This is an **offline, multilingual** content-safety guard - the gap the other classifiers leave open. The bundled Defender is English-only (~0% recall off-English), and cloud content-safety APIs are per-call and PII-bound. Opir-multilang gives genuine non-English coverage locally (≈40-76% recall at 16-36% FPR across de/es/ru/ar/zh/hi on `textdetox/multilingual_toxicity_dataset`). Position it as *complementing* (not replacing) Azure Content Safety, the way Defender is positioned for English injection. See the Opir evaluation in the [Kyoto](https://github.com/filipw/kyoto) repo for the full benchmark.

**Setup:** Download `model_fp16.onnx` (~561 MB; the fp32 `model.onnx` is also published), `spm.model` and `prefix.json` from [`filip-w/opir-multilang-onnx`](https://huggingface.co/filip-w/opir-multilang-onnx), or fetch them with the Kyoto bootstrap (see [`eng/MODELS.md`](../eng/MODELS.md)):
```bash
# from a sibling checkout of the Kyoto repo
cd ../kyoto
./bootstrap-models.sh opir      # fp16 model (saved as model.onnx) + spm.model + prefix.json -> ./models/opir-multilang/
source ./models/env.sh          # exports AGENTGUARD_OPIR_ONNX_MODEL_PATH, _TOKENIZER_PATH and _PREFIX_PATH
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| ModelPath | `string` | *(required)* | Path to the Opir-multilang ONNX model file |
| TokenizerPath | `string` | *(required)* | Path to the mDeBERTa-v3 SentencePiece model (spm.model) |
| PrefixPath | `string` | *(required)* | Path to the frozen-taxonomy label prefix (prefix.json) |
| Threshold | `float` | 0.5 | Block threshold on the max per-label probability. Tunable per deployment (FPR is somewhat threshold-sensitive here) |
| MaxTokenLength | `int` | 512 | Model input size; longer input is split into windows, not truncated |
| WindowSize / WindowOverlap / MaxWindows | `int` | 512 / 128 / 32 | Window size (clamped to what fits after the label prefix), overlap, and the cap above which input is blocked; see the Defender section |
| IncludeConfidence | `bool` | true | Include the triggering label, score, and full per-label scores in result metadata |

When blocked, result metadata includes:
- `label` - the harm category with the highest score (e.g. "hate speech")
- `confidence` - that label's probability (0.0-1.0)
- `scores` - per-harm-label probabilities
- `model` - `opir-multilang-mdeberta-v3`
- `threshold` - the configured threshold

> The model is a frozen-taxonomy ONNX export distributed at [`filip-w/opir-multilang-onnx`](https://huggingface.co/filip-w/opir-multilang-onnx). The graph also bakes a `safe and benign` sentinel label (excluded from the block decision) that GLiClass needs for calibration.

## Tool Call Guardrails

`.GuardToolCalls(options?)`

Order 45, Output phase. Inspects the arguments of the tool calls a model makes for injection aimed at the systems behind the tools.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| Categories | `ToolCallInjectionCategory` | Default | Flags: `SqlInjection`, `CodeInjection` (Python/JavaScript/.NET, unsafe deserialization), `PathTraversal`, `CommandInjection`, `Ssrf` (localhost, private networks, cloud metadata endpoints, internal TLDs). `TemplateInjection` and `Xss` are opt-in (`All` includes them) |
| AllowedTools | `ISet<string>` | {} | Tools to skip entirely, e.g. one that legitimately takes SQL (case-insensitive) |
| AllowedArguments | `ISet<string>` | {} | Argument names to skip across all tools |
| PerToolAllowedArguments | `IDictionary<string, ISet<string>>` | {} | Argument names to skip for a specific tool |

When blocked, result metadata includes `violationCount`, `toolName`, `argumentName`, `category` and `violations`.

**MAF integration (`UseAgentGuard()`):** when this rule is in the policy (gated with `.When()`/`.Unless()` or not) and the inner agent has a `FunctionInvokingChatClient`, a function-invocation middleware checks each call's arguments before the tool runs. A blocked call is never executed; the model receives `ToolResultMiddlewareOptions.BlockedToolCallPlaceholder` instead (or, with `HardFail`, a `GuardrailViolationException` aborts the run). The output guardrail also evaluates the `FunctionCallContent` in each response, so a response that contains a blocked call is replaced with the violation message; this also covers tools that bypass `FunctionInvokingChatClient` (hosted tools, MCP), after the fact.

**`IChatClient` decorator (`UseAgentGuard()` on `IChatClient`):** the tool calls in each response are evaluated with its final text. Place the decorator inside a `FunctionInvokingChatClient` so every model turn is vetted before its tool calls run - outside it, calls can only be flagged after they have been executed:

```csharp
IChatClient client = new ChatClientBuilder(innerClient)
    .UseFunctionInvocation()
    .Use(inner => inner.UseAgentGuard(g => g.GuardToolCalls()))
    .Build();
```

**Manual usage:** Place tool calls in `GuardrailContext.Properties["ToolCalls"]` as `IReadOnlyList<AgentToolCall>`. An `AgentToolCall.RawContent`, when set, is scanned too, unless one of the call's arguments is allow-listed. Violations are stored in `Properties["ToolCallViolations"]`.

## Tool Result Guardrails (Indirect Injection)

`.GuardToolResults(options?)` or `.GuardToolResults(action)`

Order 47, Output phase. Detects indirect prompt injection in incoming tool call results - emails, documents, API responses - before they reach the LLM. Complements [`ToolCallGuardrailRule`](#tool-call-guardrails) (which guards outbound arguments). Inspired by [StackOneHQ/defender](https://github.com/StackOneHQ/defender).

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| Action | `ToolResultAction` | Block | `Block` to reject, `Sanitize` to remove each injection from the start of its line to the end of its paragraph |
| ToolRiskProfiles | `IDictionary<string, ToolRiskLevel>` | {} | Per-tool risk overrides (Low/Medium/High) |
| SkippedTools | `ISet<string>` | {} | Tool names to skip entirely |
| StripUnicodeControl | `bool` | true | Strip control, zero-width and Unicode tag characters from the results handed back. The patterns run on both the raw and the stripped text, so hidden characters are detected either way |
| DetectEncodedPayloads | `bool` | true | Detect base64-encoded injection payloads |
| SanitizationReplacement | `string` | `[FILTERED]` | Replacement text when sanitizing, inserted literally |
| CustomPatterns | `IReadOnlyList<(string, string, Regex)>` | [] | Additional (category, description, pattern) tuples |

**Three-tier risk-based detection:**

| Tier | Risk Level | Patterns Checked |
|------|-----------|-----------------|
| Core | All tools | Role hijacking, instruction override, ChatML/XML/JSON role token injection, HTML comment injection, zero-width chars, text direction overrides, Unicode tag characters, data exfiltration URLs, prompt leak instructions, security bypass and uncensored-mode requests, command execution directives, separator injection |
| Medium | Medium + High | Markdown hidden text and image payloads, `[INST]`/`[SYS]` blocks, hex, Unicode-escape and HTML-entity encoded content, ROT13 instructions, fullwidth-character obfuscation |
| High | High only | Base64-encoded instructions, action directives, social engineering, fake tool-output boundaries, persona and privileged-role hijacking, DAN/developer mode, leetspeak injection keywords |

**Built-in tool risk profiles:**

| Risk Level | Default Tools |
|-----------|--------------|
| High | gmail, email, send_email, read_email, outlook, slack, teams, discord, chat, message, sms |
| Medium | search, web_search, browse, read_file, get_document, github, jira, confluence |
| Low | calculator, get_weather, get_time |

Tools not in the profile default to Medium. Tool names containing "email", "mail", "message", "chat", "slack", or "sms" are heuristically classified as High.

**MAF integration (`UseAgentGuard()`):** When this rule is in the policy (gated with `.When()`/`.Unless()` or not), tool results are automatically intercepted via the MAF function-invocation middleware (requires `FunctionInvokingChatClient` in the inner agent). Each tool result is evaluated BEFORE being fed back to the LLM; string results from `AIFunctionFactory` tools are evaluated as the plain text the tool returned. The policy's output-phase rules whose order is in `IncludeRuleOrders` (by default PII 20, secrets 22 and LLM PII 25) run on the result first and can rewrite or block it; this rule then inspects what they produced. Blocked results are replaced with `BlockedPlaceholder` (or, with `HardFail`, a `GuardrailViolationException` aborts the run); sanitized results substitute the modified content. The same middleware checks tool-call arguments before the tool runs (see [Tool Call Guardrails](#tool-call-guardrails)). As a safety net for tools that bypass `FunctionInvokingChatClient` (hosted tools, MCP), the post-hoc output guardrail also extracts `FunctionCallContent` and `FunctionResultContent` from the response messages. Configure via `ToolResultMiddlewareOptions` on the `UseAgentGuard(policy, toolResultOptions, logger, ledger)` overload (`Enabled`, `IncludeRuleOrders`, `BlockedPlaceholder`, `BlockedToolCallPlaceholder`, `HardFail`).

The `IChatClient` decorator evaluates the tool results contained in each response it returns, together with the response's final text.

**Manual usage:** Place tool results in `GuardrailContext.Properties["ToolResults"]` as `IReadOnlyList<ToolResultEntry>`. When the rule sanitizes an injection, or strips hidden characters from a result it lets through, the cleaned results are written to `Properties["SanitizedToolResults"]` - use them in place of the originals. Violations are stored in `Properties["ToolResultViolations"]`.

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

// With options (custom text extractor, logger, decision ledger)
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

Gate the **most recently added** rule behind a runtime predicate, evaluated per request. When the predicate returns false (`.When`) or true (`.Unless`), the rule is skipped and passes through; `Name`, `Phase` and `Order` are preserved so execution order and telemetry are unchanged. Both sync (`Func<GuardrailContext, bool>`) and async (`Func<GuardrailContext, CancellationToken, ValueTask<bool>>`) predicates are supported. Internally this wraps the rule in a `ConditionalGuardrailRule`, which you can also construct directly and pass to `.AddRule(...)`. A gated rule otherwise behaves like the rule it wraps: it keeps its streaming mode, the MAF tool middleware recognizes a gated `ToolCallGuardrailRule` or `ToolResultGuardrailRule`, and disposing the policy disposes it. Code of your own that looks for a rule type can call `rule.Unwrap()` (`AgentGuard.Core.Rules`) to get the rule behind the gates.

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
