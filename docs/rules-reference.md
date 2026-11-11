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
| DecodeBase64 | `bool` | true | Detect and decode base64-encoded segments, in the standard or the URL-safe alphabet, with or without padding, also when joined to another word with `-` or `_` |
| DecodeHex | `bool` | true | Decode hex escape sequences (`\x69\x67...`) |
| DetectReversedText | `bool` | true | Detect reversed text and hand it on read forwards: a message reversed as a whole, or one whose words are reversed in place, also behind a plain-text preamble (two injection keywords spelled backwards are enough) |
| NormalizeUnicode | `bool` | true | Fold look-alike characters used to disguise Latin text: fullwidth letters (with the digits and punctuation in the same run), mathematical alphanumeric symbols, and circled or squared letters (the five that double as emoji, such as the parking sign, keep their emoji form when a variation selector marks them as one). Cyrillic and Greek look-alikes are folded to Latin only inside words that also contain Latin letters, so Russian or Greek text passes unchanged, as do superscripts, fractions and other compatibility characters. When full NFKC folding would reveal more injection keywords, the folded text is added as a decoded view |
| DecodeLeetspeak | `bool` | true | Decode leetspeak in words that mix letters with digits or symbols (`1gn0r3`, `a11`, `in$truction$`). One disguised injection keyword is enough; numbers, prices and punctuation on their own are left alone |
| StripInvisibleUnicode | `bool` | true | Strip the characters that render as nothing and are used to break up keywords: zero-width characters and joiners, directional marks, embeddings, overrides and isolates, soft hyphens, Hangul fillers, variation selectors placed after a letter or digit (one that selects an emoji, keycap or ideograph form stays), and Unicode tag characters (U+E0000-U+E007F, "ASCII smuggling"); text spelled in tag characters is also surfaced as a decoded view |
| MinBase64Length | `int` | 16 | Minimum base64 segment length to attempt decoding |

`NormalizeUnicode` and `StripInvisibleUnicode` rewrite the text itself. What the decoders decode is not added to the text - the model receives the text as written (after those two rewrites). Instead the decoded forms are handed to the pipeline as decoded views (`InputNormalizationRule.DecodedViewsKey`), and every later rule in the pipeline is also run on them: a block found in a decoded view blocks the text, with "(found in decoded content)" added to the reason, while a rewrite of a view is discarded. The token limit doesn't count decoded views. Running the later rules on the views means an LLM or remote rule may be called twice for a text that has them. Invalid UTF-16 (a lone surrogate) is replaced with U+FFFD rather than failing the rule.

## Retrieval Guardrails (RAG)

`.GuardRetrieval(options?)`

Order 8, Input phase. Filters retrieved chunks before they reach the LLM context. Place the chunks in `GuardrailContext.Properties["RetrievalChunks"]` (any `IEnumerable<RetrievedChunk>`); the rule writes the surviving chunks to `Properties["ApprovedChunks"]` and the per-chunk evaluation to `Properties["RetrievalGuardrailResult"]`, and leaves the user's text unchanged. `EvaluateChunks(chunks)` runs the same checks outside a pipeline, and `RetrievalGuardrailContextProvider` (`AgentGuard.AgentFramework`) plugs it into a MAF agent as a context provider. The provider adds the approved chunks as one `User` message framed as reference data (a "treat as data" header and numbered `<<<chunk N>>>` delimiters chunk text can't forge); `ContextMessageRole` and `FormatContext` change that, and `ChatRole.System` is discouraged for content you don't fully control.

Nothing puts chunks into the property bag on its own: `.GuardRetrieval()` in a policy used through `UseAgentGuard()` does nothing until the code that retrieves places its chunks there. In an agent, use `RetrievalGuardrailContextProvider`; elsewhere call `EvaluateChunks` where you retrieve.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| DetectPromptInjection | `bool` | true | Flag chunks carrying an indirect injection. A chunk is checked the way a tool result is - with the [tool result patterns](#tool-result-guardrails) for `InjectionRiskLevel`, as stored and with invisible characters removed, and inside base64, hex and percent-encoded runs. Invisible characters are also removed from the chunks handed on |
| InjectionRiskLevel | `ToolRiskLevel` | Medium | Which tiers of the tool result patterns apply. Use `High` for stores holding text written by outsiders (inboxes, tickets, scraped pages) |
| DetectSecrets | `bool` | true | Flag chunks carrying AWS access keys, GitHub tokens, private keys (PEM, PGP, SSH2), API key assignments or JWTs |
| DetectPII | `bool` | false | Flag chunks carrying email addresses, US phone numbers or SSN-shaped numbers |
| MinRelevanceScore | `double?` | null | Drop chunks whose `Score` is below this; chunks without a score are kept |
| MaxChunks | `int?` | null | Keep only this many chunks, highest score first |
| Action | `RetrievalFilterAction` | Remove | `Remove` drops a flagged chunk; `Sanitize` keeps it, with secrets and PII replaced where they stand and an injected instruction removed together with the rest of its paragraph |
| CustomFilters | `IList<(string Name, Func<string, bool> Predicate)>` | [] | Extra checks on the chunk text; when sanitizing, a chunk a custom filter flags is replaced entirely |
| SanitizationReplacement | `string` | `[FILTERED]` | Replacement text when sanitizing |

With `Sanitize`, every filter a chunk trips is applied. A private key is replaced as a whole block - from its `-----BEGIN ... PRIVATE KEY-----` line (RSA, EC, DSA, OPENSSH, ENCRYPTED, PKCS#8, PGP private or secret key block, or SSH2) through the matching end line, or to the end of the chunk when that line is missing. Chunks dropped by `MinRelevanceScore` or `MaxChunks` are removed whatever the `Action`. A chunk that could not be scanned within the pattern time budget is removed under either action (filter `scan-incomplete`), and the result is then marked `IsError`. When chunks are removed, the result carries `filteredCount`, `totalChunks`, `approvedCount` and `incompleteScans` metadata.

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
| Low (Core) | Direct instruction override, however it is worded ("ignore all of the previous instructions", "disregard your rules", "forget everything you were told"); personas without rules ("you are now DAN", "pretend you are an AI without restrictions", "developer mode enabled"); attempts to switch off the assistant's safeguards; chat-role markers followed by a directive, and forged assistant turns that start the answer; end sequence injection (chat-template tokens, fake role tags, bracketed frames, separator lines and headings that name the system or its instructions); instructions in HTML comments; variable expansion |
| Medium (+Medium) | + System prompt extraction, forged assistant turns (`Assistant:` at the start of a line), jailbreak keywords and personas described as having no rules, rule addition, standing orders to obey ("from now on you must comply"), anti-harm coercion, contradiction ("your real instructions are...") |
| High (+High) | + Plain role play ("pretend you are ...", "you are now a ..."), framing attacks (hypothetical/fictional contexts), inversion/double-negative extraction, link injection, bare chat-role markers (`System:`, `User:`, `AI:` at the start of a line), system-role JSON objects (`"role": "system"`), any standing order ("from now on you should ..."), bare "no restrictions" phrasing |

The Low and Medium tiers are written to leave ordinary requests alone. What a user says about their own messages ("ignore my previous instructions, I changed my mind"), about a thing ("ignore the above email"), or negated ("don't forget the previous instructions") is not an override; a filter or restriction that is not the assistant's ("disable the filter in Excel", "a plan with no restrictions") is not a bypass; "what are your rules for returns" is not prompt extraction; `### System Requirements`, a PEM header and `Model: ThinkPad` at the start of a line are not frames or forged turns. Role play is the one deliberate trade: "pretend you are an interviewer" and "pretend you are my late grandmother" read the same to a pattern, so plain role play is only matched at High, where pasted transcripts, API payloads and standing preferences match too.

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
| OnError | `ErrorBehavior` | FailClosed | What to do when the tokenizer or the model fails on an input: FailClosed (block), Warn (pass, surfaced as a warning), FailOpen (pass quietly). The default differs from the remote and regex rules: the model is local, so a failure is caused by the input, and failing open would let a crafted input switch the classifier off |
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

The options are validated when the rule is constructed: a threshold that is NaN or outside 0.0-1.0, a non-positive `TemperatureT`, a `MaxTokenLength` below 3, a `WindowSize` below 1, or a `WindowOverlap` that is negative or not smaller than `WindowSize` throws `ArgumentOutOfRangeException`. An undefined `OnError` value throws too. The same checks apply to the DeBERTa, PIGuard and Opir rules below. The ONNX rules are `IDisposable` (disposing the policy disposes them, and disposing twice is safe); evaluating a disposed rule throws `ObjectDisposedException`. Disposing a rule while evaluations are running is safe: they finish, and the model session is released when the last one completes.

**Failures.** An input the tokenizer or the model can't process is an error result decided by `OnError` (`IsError` set, exception type and message in `errorDetail`), not an exception out of the pipeline. Cancellation and use after disposal still throw. Unpaired UTF-16 surrogates are replaced with U+FFFD before classification, so malformed text is classified rather than failing.

**Long input.** Text that fits in one window is classified in a single call. Longer text is split into overlapping windows that cover all of it; the rule blocks if any window blocks, and the metadata of the worst window adds `windowIndex`, `windowCount`, `windowStart` and `windowLength`. Cost grows with length (about 5 ms per window on a laptop CPU). Because every passage is classified, long technical or instructional text (man pages, READMEs) is blocked more often than short prompts - raise `WindowSize` (up to `MaxTokenLength - 2`) to trade dilution resistance for fewer such blocks. Each window is checked against what the model session actually encodes and split further when it would not fit, so nothing is silently truncated. Defender reads line breaks and tabs as word separators, and classifies a word of more than 100 characters in pieces rather than as one unknown token (`windowStart` / `windowLength` still refer to the original text); long unbroken blobs such as base64 therefore cost more windows and can reach `MaxWindows`.

**Limitations.**

- **English-centric.** Trained mostly on English, the model over-fires on non-English benign input (e.g. ordinary German questions). For non-English users, raise `MainThreshold` for that segment rather than disabling the rule (see [Dynamic rule enabling](#dynamic-rule-enabling)). Tradeoff: a higher threshold also weakens detection of *native-language* attacks, so pair it with a multilingual classifier for real coverage.
- **Text without word boundaries.** An injection written with no separators at all scores lower than the same words spaced (0.64-0.77 against 0.97 measured), and a word of up to 100 characters holding a character outside the vocabulary is one unknown token. Pair Defender with `NormalizeInput()` and the regex rule for obfuscated input.
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
| OnError | `ErrorBehavior` | FailClosed | What to do when the tokenizer or the model fails on an input: FailClosed (block), Warn (pass, surfaced as a warning), FailOpen (pass quietly). See the Defender section |
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
| OnError | `ErrorBehavior` | FailClosed | What to do when the tokenizer or the model fails on an input: FailClosed (block), Warn (pass, surfaced as a warning), FailOpen (pass quietly). See the Defender section |
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
| InjectionLabels | `ISet<string>` | jailbreak, injection, prompt_injection, malicious, unsafe, harmful, attack, LABEL_1 | Labels indicating injection. Labels are compared on letters and digits only, ignoring case, so `prompt_injection`, `prompt-injection` and `PromptInjection` are one label. Must not be empty or share a label with `SafeLabels`. Read once when the rule is constructed |
| SafeLabels | `ISet<string>` | safe, benign, legit, legitimate, clean, normal, harmless, LABEL_0 | Labels that mean the text is clean. A predicted label in neither set is an error handled by `OnError`, not a pass - add your model's own labels (and swap `LABEL_0` / `LABEL_1` if it numbers them the other way round) |
| MaxCharactersPerRequest | `int` | 2000 | Longer text is classified in overlapping windows, one request each, split at whitespace; an injection in any window blocks |
| WindowOverlapCharacters | `int?` | a fifth of the window | Characters consecutive windows share; at most half of `MaxCharactersPerRequest` |
| MaxRequests | `int` | 32 | Text needing more requests is an error handled by `OnError` (under FailClosed nothing is sent; otherwise the first windows are still checked and an injection there still blocks); 0 = no limit |
| Threshold | `float` | 0.5 | Confidence threshold (0.0-1.0; NaN or out of range throws when the rule is constructed) |
| IncludeConfidence | `bool` | true | Include the score in result metadata |
| OnError | `ErrorBehavior` | FailOpen | What to do on error: FailOpen (pass quietly), Warn (pass, surfaced as a warning), FailClosed (block) |
| Timeout | `TimeSpan` | 10s | Timeout of each request; must be positive or `Timeout.InfiniteTimeSpan` |

The rule blocks when an injection label's own score reaches the threshold - the top label's, or any injection label's when the endpoint returns a score for every label, so thresholds below 0.5 work with such endpoints. A response the classifier can't read (no entries, an entry without a label, a score outside 0-1, an unknown shape) or a predicted label the rule doesn't know is an error handled by `OnError`, not a pass. When the text was split, a block's metadata adds `window` and `windowCount`; windows are sent one at a time and the first failure or injection ends the evaluation.

When blocked, result metadata includes:
- `label` - the injection label that reached the threshold (e.g. "jailbreak"; the highest-scoring one when several do)
- `confidence` - that label's score (0.0-1.0)
- `model` - model name (if configured)
- `threshold` - the configured threshold

**Setting up a Sentinel-v2 endpoint:** any small HTTP app wrapping `transformers.pipeline("text-classification", ...)` (for example FastAPI + uvicorn) works. The classifier sends `POST {EndpointUrl}` with `{"inputs": "<text>"}` (`HuggingFace`, the default) or `{"text": "<text>"}` (`Simple`), and reads the pipeline's output - a single `{"label": "jailbreak", "score": 0.99}` object, a list of them, or a nested `[[...]]` (every inner list is read). The highest-scoring label is the prediction, and every label's score is available as `ClassificationResult.Scores`.

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

**How judge replies are read (all LLM rules).** The judge's reply is parsed tolerantly. These are all understood:
- markdown emphasis and code markers;
- `Verdict:`, `Answer:`, `Classification:`, `Result:`, `Label:`, `Decision:` and similar prefixes, including one on a line of its own;
- a reason on the same line or on the lines below, including one that starts with a negation word ("VIOLATION: no disclaimer was included");
- a positive verdict on a later line, below a preamble such as "Here is my classification:";
- reasoning in `<think>`, `<thinking>` or `<reasoning>` blocks, even when the opening tag is missing;
- a JSON object with a `verdict`, `classification`, `answer` or `result` field.

A reply that negates or questions its own finding ("PII: none", "INJECTION - not found", "INJECTION?", "SAFE: false"), or that has no verdict at all, is unparseable and goes through the rule's `errorBehavior`, which fails open by default. A negative verdict is only read from the verdict line itself, never from further down: text the judge quotes from what it is judging can therefore cause a block, but not a pass. For the same reason a positive verdict on the opening line stands even when a closing reasoning tag appears later in the reply. The error detail quotes the judge's text only when content capture (`AGENTGUARD_CAPTURE_CONTENT`) is on.

The conversation history given to a judge includes tool calls (name and arguments) and tool results, fenced like message text and capped in size: 1,000 characters per call's arguments, 2,000 per result, and 12,000 in all, with the most recent kept first. Custom `LlmGuardrailRule` subclasses get the same parsing from `ExtractVerdictLine`/`ClassifyVerdict`.

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
runs the rule on input and output, `false` on input only; `OnError` (default `FailOpen`) decides what a
recognizer failure does - an unreachable remote or Azure detector, say. Under `FailOpen` and `Warn` the
text continues with whatever the working recognizers found redacted and the result has `IsError` set;
under `FailClosed` it is blocked.

`PiiOptions.Entities` is checked when the rule is built: a name no recognizer detects (a misspelling, or
a country entity whose pack is not enabled) throws `ArgumentException` listing the names that are
detected, instead of silently switching that detection off. Names are matched ignoring case.

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
| Categories | `SecretCategory` | Default | Flags: `ApiKey` (API key/token assignments, bearer tokens, Slack tokens, and quoted secret fields such as `"api_key": "..."` or `'password': '...'`), `AwsCredential`, `ConnectionString` (connection strings with a password, and any URI with a password in its user info - `postgres://`, `mysql://`, `mongodb(+srv)://`, `redis://`, `amqp://`, ...), `PrivateKey` (PEM, PGP and SSH2 blocks), `JwtToken`, `GitHubToken` (classic and fine-grained `github_pat_`), `AzureKey` (storage account and subscription keys). `GenericHighEntropy` is opt-in (`All` includes it) |
| Action | `SecretAction` | Block | `Block` rejects the text; `Redact` replaces each finding (high-entropy ones included) with `Replacement` |
| Replacement | `string` | `[SECRET_REDACTED]` | Replacement text when redacting, inserted literally. Where the secret is a value - a quoted field, the password of a connection string or URI, a token assigned to a secret-like key - only the value is replaced, so a URI keeps its user name and host |
| CustomPatterns | `IDictionary<string, string>` | {} | Additional patterns: label -> regex (culture-invariant). A pattern with a group named `secret` has only that group replaced when redacting |
| MinHighEntropyLength | `int` | 20 | Shortest token `GenericHighEntropy` considers (at least 8). A value assigned to a secret-like key name (key, secret, token, password, pwd, auth, credential, ...) is considered from 12 characters |
| OnError | `ErrorBehavior` | FailOpen | Outcome when a pattern timed out and nothing else was found: FailOpen (pass, with `IsError` set), Warn (pass, surfaced as a warning), FailClosed (block) |

A private key matches as a whole block - from the `-----BEGIN ... PRIVATE KEY-----` line (RSA, EC, DSA, OPENSSH, ENCRYPTED, PKCS#8, PGP's `PRIVATE KEY BLOCK` and `SECRET KEY BLOCK`, and the SSH2 `---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----` form) through the matching end line, or to the end of the text when that line is missing - so `Redact` removes the key body, not just its header. Placeholder values (`${VAR}`, `$VAR`, `<password>`, `%PASSWORD%`, `****`, `changeme`, `YOUR_API_KEY`, `your-api-key-here`) are not reported, and neither is a value that is code rather than a key (`apiKey: process.env.OPENAI_API_KEY`). A value has to be a placeholder as a whole: a password that only starts like one (`$uperS3cret!9`, `Enterprise2024!`, `(Tr0ub4dor&3)`) is a password. In a `key=value` connection string the password may be quoted and may come before or after the host key; `SharedAccessKey=` and `AccountKey=` values are reported as well.

A pattern that exceeds its 200 ms match timeout is skipped and the others still run. When nothing else was found, the result is an error decided by `OnError` (default `FailOpen`) with `IsError` set, not a clean pass; when `Redact` did replace something, the result also has `IsError` and `IsWarning` set, since the text may hold what the unfinished pattern looks for.

`GenericHighEntropy` flags a token when its entropy reaches 90% (85% next to a secret-like key name) of what a random string of the same length and character set - hex, single-case alphanumeric, base64 or printable ASCII - typically has. Hex strings and tokens inside URLs only count when they are assigned to a secret-like key name. Git SHAs, UUIDs, labelled and Subresource Integrity hashes, data URIs and base64 images, long words and camelCase/PascalCase identifiers, file paths, URLs without credentials and JWTs (left to the JWT pattern) are not flagged. A bare 40-character AWS secret key is only flagged when related context appears in the text (`aws` as a word, `secret access key` however it is separated, or an `AKIA...` access key id) and it is not forty hex digits, which is a commit id. A 32-character hex Azure subscription key is only flagged when a key is named (`ocp-apim-subscription-key`, `subscription key`, `AZURE_..._KEY`, `api key`, ...). When blocked, result metadata includes `detectedCategories` (e.g. `aws-access-key`, `private-key`).

## PII Detection (LLM)

`.DetectPIIWithLlm(chatClient, options?)`

Order 25, Both phases. Catches unstructured PII (names, addresses, contextual identifiers) that regex misses.

| Option | Type | Default |
|--------|------|---------|
| Action | `PiiAction` | Redact |
| SystemPrompt | `string?` | null (built-in templates) |
| ValidateRedaction | `bool` | true |

`PiiAction.Block` returns a blocked result. `PiiAction.Redact` reads the judge's redacted version - everything after its `REDACTED:` marker, across all lines (the marker may also sit on its own line) - and applies it to the original rather than taking it as the new text.

The judge's version is accepted when it is the original with stretches replaced by placeholders (`[REDACTED]`, any other bracketed label, `<EMAIL_ADDRESS>`, `***`): the text between its placeholders has to appear in the original, in order, from its first word to its last, ignoring spacing and capitalization. The result is then the original with those stretches swapped for the placeholders, so everything that is kept is exactly what was written. A reply that changes other text, stops early, comes back unchanged, drops the data without a placeholder, or replaces more than 256 characters with one placeholder is a failed judgment: the result has `IsError` set and the rule's `ErrorBehavior` decides whether the text passes (the default) or is blocked. A message that was already redacted on an earlier turn passes.

Set `ValidateRedaction = false` only with a custom `SystemPrompt` that redacts some other way (removing the data, substituting made-up values); the judge's reply then replaces the text as it is.

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

Counts tokens with `Microsoft.ML.Tokenizers`, using the cl100k_base encoding by default. `TokenLimitOptions.TokenizerModel` takes an encoding name (cl100k_base, o200k_base, o200k_harmony, p50k_base, p50k_edit, r50k_base) or an OpenAI model name such as `gpt-4o`, matched case-insensitively; an unknown name, or a `MaxTokens` below 1, throws when the rule is constructed. The cl100k_base and o200k_base vocabularies ship with the package. For an encoding whose vocabulary isn't installed (p50k and r50k), the rule estimates the count per script: about 4 ASCII characters per token, one token per CJK, Kana, Hangul, fullwidth or emoji character, and 2 characters per token for other text. `Truncate` cuts at a token boundary and never exceeds the budget.

Text is tokenized in bounded segments, so the check stays linear in the length of the text even for one long unbroken run. Text longer than `MaxTokens` × `TokenLimitOptions.MaxCharactersPerToken` (default 16) characters - and at least 16,384 characters - is over the limit without being tokenized: `Reject` blocks it, `Truncate` cuts it to that length first, `Warn` reports its character count.

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
| OnError | `ErrorBehavior` | FailOpen | What to do when there is no classifier or the classifier reports a failure: FailOpen (pass quietly), Warn (pass, surfaced as a warning), FailClosed (block) |

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
| OnError | `ErrorBehavior` | FailClosed | What to do when the tokenizer or the model fails on an input: FailClosed (block), Warn (pass, surfaced as a warning), FailOpen (pass quietly). See the Defender section |
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
| Categories | `ToolCallInjectionCategory` | Default | Flags: `SqlInjection`, `CodeInjection` (Python/JavaScript/.NET, unsafe deserialization), `PathTraversal`, `CommandInjection`, `Ssrf` (localhost, private networks, cloud metadata endpoints, internal TLDs, unqualified host names). `TemplateInjection` and `Xss` are opt-in (`All` includes them) |
| AllowedTools | `ISet<string>` | {} | Tools to skip entirely, e.g. one that legitimately takes SQL (case-insensitive) |
| AllowedArguments | `ISet<string>` | {} | Argument names to skip across all tools |
| PerToolAllowedArguments | `IDictionary<string, ISet<string>>` | {} | Argument names to skip for a specific tool |

Each argument is checked as written and in up to three percent-decoded layers (UTF-8 escapes, overlong forms and `%uXXXX` included). An argument that is a JSON object or array is also checked value by value - each string inside it, at any depth, as if it were an argument of its own (up to 512 values; a string that is JSON in turn is opened once more) - so a nested value such as `{"target":{"host":"127.0.0.1"}}`, or one written with `\u` escapes, is seen as the tool will read it:

- **SSRF** - hosts are parsed rather than pattern-matched. The parser handles userinfo (everything up to the last `@`, sub-delimiters such as `;`, `,` and `!` included, however long), ports and brackets, any scheme, backslash forms and `//host`; a URL with a `scheme://` authority is also checked with the host `System.Uri` resolves. Hosts are percent-decoded and fullwidth-folded, the characters a resolver ignores (soft hyphens, zero-width characters) are removed, and a trailing dot is dropped. Decimal, hex, octal and short IPv4 forms (`2130706433`, `0x7f000001`, `0177.0.0.1`, `127.1`) resolve to their address, and an IPv4 address embedded in IPv6 (mapped, compatible or NAT64) is judged as that IPv4 address. Loopback, private, link-local, `0.0.0.0/8` and `100.64.0.0/10` addresses are internal. So are the cloud metadata endpoints (Azure's WireServer `168.63.129.16` included), `localhost`, the `.internal`, `.local`, `.corp`, `.lan`, `.intranet`, `.home.arpa` and `.svc` suffixes (`kubernetes.default.svc`), and, in an `http`, `https`, `ws`, `wss` or `ftp` URL, any host name without a dot (`http://redis:6379/`), which can only be a machine on the caller's own network. App links such as `slack://channel` are not affected. No DNS lookups are made, so a public name that resolves to an internal address is not caught.
- **Path traversal** - backslashes are normalized, repeated slashes collapsed, `.` segments dropped (`/etc/./passwd` is `/etc/passwd`), and `..;` segments count as parent segments. Sensitive paths are matched after `name/..` pairs are resolved: `/etc/passwd`, `shadow`, `sudoers` and the SSH and Kubernetes directories under `/etc`; `/proc/<pid>/` and `/proc/self/`; `.ssh/`, `.aws/credentials`, `.azure/`, `.kube/config`, `.docker/config.json`, `.config/gcloud/`, `.gnupg/`, `.git-credentials`, `.netrc`, `.pgpass`, `.npmrc`, `.pypirc` and shell history files under any directory; `/root/`; `/run/secrets/` and `/var/run/secrets/`; the Docker socket; Windows system files (`system32`, `win.ini`, `boot.ini`, the SAM hive, `NTUSER.DAT`, the credential store); and an argument that is nothing but a path to a `.env` file. A traversal that only appears after decoding (`..%2f`, `%2e%2e%5c`, `%252e%252e%252f`) is reported as encoded traversal.
- **Command injection** - command chaining with `&&`, `||`, `;`, `|` or `&`, and raw or encoded line breaks; the command may be written with its path (`; /bin/rm -rf`). A command name that is also an English word or a column name (`rm`, `cat`, `find`, `id`, `python`, ...) only counts when an option, path, `$`, quote or URL follows it, or when it ends the line after an operator; alone on a line only `id`, `ls`, `env` and the shells do. `$(...)` and backticks count when what they hold starts with a command, so `$(document)`, `$(VERSION)` and "use `git status` to check" are left alone.
- **Code injection** - calls, not words: `compile(` without a space, the `Function` constructor rather than the word "function", `subprocess.check_output(`, `importlib.import_module(`, `require('child_process')`.
- **SQL injection** - quoted and unquoted tautologies (`' OR 'a'='a`, `1 OR 1=1`, `1 or true`) and the same comparison after `AND` (`' AND '1'='1`). Block comments are read the way the database reads them, so `UNION/**/SELECT` and `/*!50000 UNION*/ SELECT` count as `UNION SELECT`. A `--` written straight onto a closing quote (`admin'-- `) counts wherever it stands. `EXEC` needs a call shape (`EXEC(`, `EXEC sp_`, `EXEC xp_`, `EXEC @`), and a `--` or `#` separated from the quote by a space counts only when it ends the line. After a `;` the keyword has to open a statement (`; UPDATE users SET`, `; SELECT ... FROM`, `; DROP TABLE`), and `INSERT INTO` / `DELETE FROM` have to be followed by a name rather than "my" or "the". Prose such as "execute the plan", "I fixed the bug; update the ticket", "delete from my calendar the 3pm meeting", a search for "C#", or an email signature is not flagged.

When blocked, result metadata includes `violationCount`, `toolName`, `argumentName`, `category` and `violations`.

**MAF integration (`UseAgentGuard()`):** when this rule is in the policy (gated with `.When()`/`.Unless()` or not) and the inner agent has a `FunctionInvokingChatClient`, a function-invocation middleware checks each call's arguments before the tool runs. A blocked call is never executed; the model receives `ToolResultMiddlewareOptions.BlockedToolCallPlaceholder` instead. With `HardFail`, the violation stops the run instead: the model is not called again, calls it made in the same turn are answered with a not-run placeholder (so the saved history has no unanswered call), and `RunAsync`/`RunStreamingAsync` throw `GuardrailViolationException`. The interception runs as MAF function-invocation middleware, which MAF supports only for runs whose options are `null` or a `ChatClientAgentRunOptions`. The output guardrail also evaluates the `FunctionCallContent` in each response, so a response that contains a blocked call is replaced with the violation message; this also covers tools that bypass `FunctionInvokingChatClient` (hosted tools, MCP), after the fact.

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
| StripUnicodeControl | `bool` | true | Strip control, zero-width, invisible-operator and Unicode tag characters from the results handed back. The patterns run on both the raw and the stripped text, so hidden characters are detected either way |
| DetectEncodedPayloads | `bool` | true | Decode encoded runs - base64/base64url (24+ characters, fixed-width wrapped blocks rejoined), hex (contiguous or `\x` escapes) and percent-encoding - that decode to text, and run the same patterns on the decoded text. Findings carry `Encoding` (`base64`, `hex` or `percent`) and a description suffix such as "(base64-encoded)"; with `Sanitize`, the encoded run is replaced. JWTs are not decoded. At most 1,024 runs and 256K encoded characters are decoded per result |
| SanitizationReplacement | `string` | `[FILTERED]` | Replacement text when sanitizing, inserted literally |
| CustomPatterns | `IReadOnlyList<(string, string, Regex)>` | [] | Additional (category, description, pattern) tuples |
| OnError | `ErrorBehavior` | FailOpen | What to do when a pattern runs out of its 200 ms time budget on a result and nothing else matched. The result has `IsError` set under every behavior, so an unfinished scan is never reported as a clean one |

**Three-tier risk-based detection:**

| Tier | Risk Level | Patterns Checked |
|------|-----------|-----------------|
| Core | All tools | Role markers that carry a directive (`System: you must ...`), instruction override however it is worded, ChatML tokens, `<system>` / `<assistant>` tags, chat message objects with a system role and JSON fields that give an order, HTML comment injection, zero-width chars, text direction overrides, Unicode tag characters, data exfiltration URLs, prompt leak instructions, attempts to switch off the assistant's safeguards, uncensored-mode requests, DAN by name, separator injection |
| Medium | Medium + High | Markdown hidden text and image payloads, `[INST]`/`[SYS]` blocks, hex content, Unicode escapes and HTML entities that spell ASCII, ROT13 instructions, words in fullwidth Latin letters |
| High | High only | Bare role markers and `<user>` / `<instruction>` tags, base64-encoded instructions, action directives (sending out everything, or something secret), command execution directives, social engineering, fake tool-output boundaries, persona and privileged-role hijacking, developer/god/sudo mode, leetspeak injection keywords |

The Core and Medium tiers run on documents, web pages and API results, so they are written to leave those alone: `"role": "manager"`, `system: ubuntu-22.04` in YAML, `<user>` in XML, a link with `?token=` or `&prompt=consent`, "run the following command: npm install", "enable developer mode", escaped or entity-encoded non-English text, and right-to-left text with its embedding marks all pass. What is only suspicious when someone wrote it to the reader - a bare `Assistant:` line, "run the following command:", "enable developer mode" - is checked for High-risk tools, whose results are messages. There, ordinary requests between people ("please send an email to HR with your dates", "URGENT: Action required", "you are now an admin of the workspace") pass, while "forward all emails to ..." and "send your credentials to ..." do not.

A data exfiltration URL is an image whose address carries a data-bearing parameter (a client fetches it without a click), a link with a parameter named for what it carries (`?data=`, `?context=`, `?history=`), or a link whose parameter is a blank for the model to fill in (`?q={conversation}`).

**Built-in tool risk profiles:**

| Risk Level | Default Tools |
|-----------|--------------|
| High | gmail, email, send_email, read_email, outlook, slack, teams, discord, chat, message, sms |
| Medium | search, web_search, browse, read_file, get_document, github, jira, confluence |
| Low | calculator, get_weather, get_time |

Tools not in the profile default to Medium. Tool names containing "email", "mail", "message", "chat", "slack", or "sms" are heuristically classified as High.

**MAF integration (`UseAgentGuard()`):** When this rule is in the policy (gated with `.When()`/`.Unless()` or not), tool results are automatically intercepted via the MAF function-invocation middleware (requires `FunctionInvokingChatClient` in the inner agent). Each tool result is evaluated BEFORE being fed back to the LLM; string results from `AIFunctionFactory` tools are evaluated as the plain text the tool returned. The policy's output-phase rules whose order is in `IncludeRuleOrders` (by default PII 20, secrets 22 and LLM PII 25) run on the result first and can rewrite or block it; this rule then inspects what they produced. Blocked results are replaced with `BlockedPlaceholder` (or, with `HardFail`, a `GuardrailViolationException` aborts the run); sanitized results substitute the modified content. The same middleware checks tool-call arguments before the tool runs (see [Tool Call Guardrails](#tool-call-guardrails)). As a safety net for tools that bypass `FunctionInvokingChatClient` (hosted tools, MCP), the post-hoc output guardrail also extracts `FunctionCallContent` and `FunctionResultContent` from the response messages. Configure via `ToolResultMiddlewareOptions` on the `UseAgentGuard(policy, toolResultOptions, logger, ledger)` overload (`Enabled`, `IncludeRuleOrders`, `BlockedPlaceholder`, `BlockedToolCallPlaceholder`, `HardFail`).

The `IChatClient` decorator evaluates the tool results a request carries before the model reads them (which is where they arrive when the decorator sits inside a `FunctionInvokingChatClient`), and those contained in each response it returns, together with the response's final text.

**Manual usage:** Place tool results in `GuardrailContext.Properties["ToolResults"]` as `IReadOnlyList<ToolResultEntry>`. When the rule sanitizes an injection, or strips hidden characters from a result it lets through, the cleaned results are written to `Properties["SanitizedToolResults"]` - use them in place of the originals. Violations are stored in `Properties["ToolResultViolations"]`.

---

## Output/Input Validation

`.ValidateOutput(predicate, message)` / `.ValidateInput(predicate, message)`

Order 100. Simple predicate-based assertions. `ValidateOutput` judges answer text, so a response that is only tool calls - which has none - is not put to it.

Custom output rules do run for such a response, so that a rule of yours can inspect its tool calls: `GuardrailContext.Text` is then empty and `GuardrailContext.Properties` holds `ChatMessageGuard.ToolContentOnlyKey`. A rule that judges the answer should pass when that key is present.

## Output Policy Enforcement (LLM)

`.EnforceOutputPolicy(chatClient, policyDescription)` or `.EnforceOutputPolicyWithLlm(chatClient, options)`

Checks whether the agent's response violates a custom policy constraint. Useful for brand safety, compliance, and operational guardrails.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| PolicyDescription | `string` | *(required)* | Natural language description of the policy to enforce |
| Action | `OutputPolicyAction` | Block | `Block` to reject, `Warn` to pass and surface the finding as a warning |
| SystemPrompt | `string?` | *(built-in)* | Custom system prompt (use `{policy}` placeholder) |

- **Order**: 55, **Phase**: Output
- Response format: `COMPLIANT` or `VIOLATION|reason:<reason>`
- When `Action = Warn`, the result passes with `IsWarning` set and a reason, so it is logged at Warning level and listed in `GuardrailPipelineResult.Warnings`; it includes `Metadata["violation_reason"]` and `Metadata["policy"]`

---

## Groundedness Checking (LLM)

`.CheckGroundedness(chatClient)` or `.CheckGroundednessWithLlm(chatClient, options?)`

Detects hallucinated facts and claims not supported by the conversation context. Uses `GuardrailContext.Messages` to provide conversation history to the LLM.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| Action | `GroundednessAction` | Block | `Block` to reject, `Warn` to pass and surface the finding as a warning |
| SystemPrompt | `string?` | *(built-in)* | Custom system prompt (use `{context}` placeholder) |

- **Order**: 65, **Phase**: Output
- Response format: `GROUNDED` or `UNGROUNDED|claim:<ungrounded claim>`
- Common knowledge facts are considered grounded even without conversation context
- When `Action = Warn`, the result passes with `IsWarning` set and a reason (logged at Warning level, listed in `GuardrailPipelineResult.Warnings`) and includes `Metadata["ungrounded_claim"]`

---

## Copyright Detection (LLM)

`.CheckCopyright(chatClient)` or `.CheckCopyrightWithLlm(chatClient, options?)`

Detects verbatim or near-verbatim reproduction of copyrighted material (song lyrics, book passages, articles, restrictively-licensed code).

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| Action | `CopyrightAction` | Block | `Block` to reject, `Warn` to pass and surface the finding as a warning |
| SystemPrompt | `string?` | *(built-in)* | Custom system prompt override |

- **Order**: 75, **Phase**: Output
- Response format: `CLEAN` or `COPYRIGHT|source:<source>|type:<lyrics|book|article|code|poem|speech|other>`
- Short quotes (<15 words) for commentary are acceptable and not flagged
- Public domain works and common phrases are not flagged
- When `Action = Warn`, the result passes with `IsWarning` set and a reason (logged at Warning level, listed in `GuardrailPipelineResult.Warnings`) and includes `Metadata["copyright_source"]` and `Metadata["copyright_type"]`

---

## Workflow Guardrails

`AgentGuard.AgentFramework` includes workflow guardrails that apply at MAF workflow step boundaries using the decorator pattern.

### `.WithGuardrails()` Extension Methods

Wraps `Executor<TInput>` or `Executor<TInput, TOutput>` with a `GuardedExecutor` (id `guarded-{innerId}`) that runs guardrails before/after the inner executor. The guarded executor stands in for the inner one:
- it declares the inner executor's protocol - the message types it handles, sends and yields, its catch-all route included - so messages the inner executor sends or yields through the workflow context are accepted;
- it takes over the inner executor's options and cross-run sharing, and forwards its lifecycle hooks: initialization, message-delivery start and end, checkpoint save and restore, reset (when the inner executor supports it) and disposal;
- messages of the inner executor's other handled types are input-guarded and then passed to the inner executor, which routes them to its own handler; what that handler returns, sends and yields is output-guarded like the main handler's;
- turn and reset signals (`TurnToken`, `ResetChatSignal`) pass through unchecked, since they carry no text.

| Executor Type | Input Guardrails | Output Guardrails | On Block |
|---------------|-----------------|-------------------|----------|
| `Executor<TInput>` (void) | Yes | Yes - the messages it sends and yields | Throws `GuardrailViolationException` |
| `Executor<TInput, TOutput>` (typed) | Yes | Yes - its result and the messages it sends and yields | Throws `GuardrailViolationException` |

Output guardrails cover what an executor emits through its `IWorkflowContext` as well as what it returns: every `SendMessageAsync` and `YieldOutputAsync` call, from a handler or a lifecycle hook, is checked before the message reaches the workflow. A blocked message is not forwarded and the call throws `GuardrailViolationException`, which fails the executor unless the handler catches it. A rewritten message is forwarded rewritten; it has to be rebuilt as the type that was sent, and a rewrite that can't be applied blocks unless `AllowUnappliedModifications` is set. A returned value is checked once, however the executor's options forward it. Events (`AddEventAsync`) are not guarded: they report to whoever runs the workflow and are not delivered to other executors, so guard any model- or user-facing text you put in a custom event yourself.

```csharp
// Builder overload
var guarded = executor.WithGuardrails(b => b.BlockPromptInjection().RedactPii());

// Pre-built policy overload
var guarded = executor.WithGuardrails(existingPolicy);

// With options (custom text extractor, logger, decision ledger)
var guarded = executor.WithGuardrails(b => b.RedactPii(),
    new GuardedExecutorOptions { TextExtractor = myExtractor });
```

### Chat payloads

Chat payloads are guarded message by message, the way the agent middleware guards them, without the text extractor:
- `ChatMessage` - its text is checked and rewritten in place, keeping attachments, other contents, role, author, id, timestamp and additional properties.
- Message collections on the way in (`List<ChatMessage>`, `ChatMessage[]`, or an interface `List<ChatMessage>` implements) and `AgentResponse` - every message is guarded as in a request, whatever its role: a blocked one is replaced with the removed-message placeholder, and a block of the newest user message blocks.
- Message collections and `AgentResponse` on the way out - every assistant message is guarded as in a response, including its reasoning and tool calls.
- In both directions the newest message with text is also checked whatever its role, since an executor's input is often another agent's response and its output a prompt for the next one.
- The result is rebuilt as the declared type; an `AgentResponse` keeps its ids, usage, finish reason, continuation token and additional properties. A collection type that can't be rebuilt (e.g. `Collection<ChatMessage>`) is blocked when a rule rewrote it, with a warning logged (see `AllowUnappliedModifications` below).

### `ITextExtractor`

Bridges every other workflow message type to a string for guardrail evaluation, and optionally rebuilds the message from rewritten text (`TryRebuild`, a default interface method that rebuilds nothing unless overridden). `DefaultTextExtractor` handles:
- `string` → the string itself
- `ChatMessage` → `.Text`
- `AgentResponse` and `IEnumerable<ChatMessage>` → the text of every message, one per line
- Objects with a public `Text` property → reflection; when the property is settable or `init`, `TryRebuild` rebuilds the message as a copy (a record's `with` copy, or a struct copy) with the rewritten `Text`
- Fallback → `ToString()`, for types that override it; a message with no `Text` and no `ToString()` of its own has no text and passes unchecked

A guarded executor asks the extractor only for types other than the chat payloads above; the chat branches serve custom extractors that delegate to it.

### `GuardrailViolationException`

Thrown when a guardrail blocks within a workflow executor. MAF surfaces this as `ExecutorFailedEvent`.

| Property | Type | Description |
|----------|------|-------------|
| `ViolationResult` | `GuardrailResult` | The blocking result (rule name, reason, severity) |
| `Phase` | `GuardrailPhase` | `Input` or `Output` |
| `ExecutorId` | `string` | ID of the inner executor that was guarded |

### Text Reconstruction

When a guardrail modifies text (e.g. PII redaction), the modification is applied to the message:
- `string` → replaced directly
- Chat payloads → rewritten as described above, keeping everything but the changed text
- Other types → rebuilt by the extractor's `TryRebuild` when it supports the type; otherwise the message is blocked (`GuardrailViolationException`) with a warning logged, so a redaction that can't be applied never lets the original through. Set `GuardedExecutorOptions.AllowUnappliedModifications = true` to pass the original on unchanged instead, with the warning

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
