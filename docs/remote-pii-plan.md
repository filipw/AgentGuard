# Remote PII detection - design & implementation plan

Status: **Phase 1 done; Phases 2-5 pending.** The next session prompt is in
`docs/remote-pii-start-prompt.md`.

Phase 1 landed in `~/dev/tasmaniandevil` (commit history there). Confirmed surface to build on:
- `EntityRecognizer`: `virtual bool RequiresAsync => false` and
  `virtual ValueTask<IReadOnlyList<RecognizerResult>> AnalyzeAsync(string text, IReadOnlyList<string> entities, CancellationToken ct = default)` (default wraps `Analyze`).
- `AnalyzerEngine.AnalyzeAsync(string text, string language = "en", IReadOnlyList<string>? entities = null, double? scoreThreshold = null, IReadOnlyList<string>? allowList = null, AllowListMatch allowListMatch = AllowListMatch.Exact, IReadOnlyList<string>? context = null, CancellationToken ct = default)` - awaits recognizers sequentially, shares a private `PostProcess`.
- `PiiEngine`: `AnalyzeAsync` / `AnonymizeAsync` / `DeidentifyAsync`; extra recognizers via the ctor param
  `PiiEngine(PiiOptions?, AnalyzerEngine?, AnonymizerEngine?, IEnumerable<EntityRecognizer>? extraRecognizers)`.
- `PiiEntities.Address = "ADDRESS"`.

**A remote/Azure recognizer subclasses `EntityRecognizer`, overrides `AnalyzeAsync`, sets
`RequiresAsync => true`, and returns `[]` from sync `Analyze`.** It must declare `SupportedEntities` and
`SupportedLanguage` (they drive registry selection and the context enhancer).

Spans two repos:
- `~/dev/tasmaniandevil` - the engine (async detection) + two new detector packages.
- `~/dev/AgentGuard` - thin guardrail glue + hosting + samples.

## Goal

Let a user run PII detection **out of process** and point AgentGuard/TasmanianDevil at it, so
model-grade entities (PERSON, ADDRESS, LOCATION) that need a heavy model can be detected without loading
that model in-process. Two flavours:

1. **Generic remote** - user wraps any service behind a small JSON contract (e.g. a TasmanianDevil +
   GLiNER sidecar in a 2 GB container). Motivating case: AgentGuard runs in a 0.5 vCPU / 500 MB container
   where the 22 MB Defender model is fine but the ~580 MB GLiNER model cannot fit.
2. **Azure PII** - shipped integration over the Azure AI Language PII REST API (native `Person` and
   `Address` categories - full street addresses off-box).

Both return **entity spans**, which flow through the existing `AnonymizerEngine`, so all operators,
reversible encrypt/decrypt, structured, allow-lists, and conflict resolution keep working. Remote is a
**detector, not a redactor**.

## Locked decisions

1. **Async is first-class in the engine (Option A)** - not a rule-level bolt-on.
2. **`TasmanianDevil.Azure` detector package + `AgentGuard.Azure` glue** (symmetric with the GLiNER split).
3. **Azure via direct REST** - the `Azure.AI.TextAnalytics` SDK is stale (no releases since 2023) and
   `Azure.AI.Language.Text` is beta/abandoned. Use HttpClient against `/language/:analyze-text`.
4. **Ship both** generic remote + Azure in v1.

### Default answers to the open questions (override at session start if desired)

1. **Concurrency:** await async recognizers **sequentially** in v1 (deterministic; sync recognizers are
   free via the `ValueTask` fast-path). `Task.WhenAll` is a later optimization.
2. **AAD:** subscription-key is the primary path; `TasmanianDevil.Azure` also takes an **optional token
   provider delegate** (`Func<CancellationToken, ValueTask<string>>`) so it needs no `Azure.Identity`
   dependency. Concrete `DefaultAzureCredential` wiring lives in `AgentGuard.Azure` (already references
   `Azure.Identity`).
3. **Azure api-version:** default to a **GA** version (`2024-11-01`), configurable. Preview
   `2025-11-15-preview` optionally unlocks redaction policies / confidence-threshold / synonyms.
4. **New canonical entity name:** `ADDRESS` (added to `PiiEntities` as a `const`; open vocabulary).

## The pivotal finding

`EntityRecognizer.Analyze` is **synchronous** and `AnalyzerEngine.Analyze` runs recognizers in a sync
`foreach`; the context enhancer, dedup, and overlap resolution all operate over the recognizer list, and
every recognizer already exposes `Context` / `SupportedEntities` / `SupportedLanguage` / `Name` / `Id`.

Therefore: **add async as a virtual on the existing base**, not a parallel interface. Registry stays
homogeneous (`List<EntityRecognizer>`), the context/dedup pipeline is untouched, the sync path is
byte-for-byte unchanged, and a remote detector is "just an async `EntityRecognizer`" - symmetric with
GLiNER being a sync one.

```
EntityRecognizer (base)
  ├─ abstract IReadOnlyList<RecognizerResult> Analyze(text, entities)     // existing, sync
  ├─ virtual  ValueTask<...> AnalyzeAsync(text, entities, ct)             // NEW: default => new(Analyze(...))
  └─ virtual  bool RequiresAsync => false                                 // NEW

Sync recognizers (regex, GLiNER): inherit the default AnalyzeAsync wrapper - no change.
Async recognizers (remote, Azure): override AnalyzeAsync (real I/O), RequiresAsync => true,
                                    Analyze(...) returns []  (sync path yields local-only).
```

Fail-open lives at the recognizer level (catch -> log -> return `[]`), matching how the guardrail rules
already behave; `AnalyzerEngine` needs no error handling or logger.

---

## Phase 1 - TasmanianDevil engine (the async spine) - DONE

Repo: `~/dev/tasmaniandevil`. Landed; see the confirmed surface at the top of this doc.

<details><summary>original Phase 1 spec (for reference)</summary>

Repo: `~/dev/tasmaniandevil`.

- `src/TasmanianDevil/Analyzer/EntityRecognizer.cs`
  - add `public virtual bool RequiresAsync => false;`
  - add `public virtual ValueTask<IReadOnlyList<RecognizerResult>> AnalyzeAsync(string text, IReadOnlyList<string> entities, CancellationToken ct = default) => new(Analyze(text, entities));`
- `src/TasmanianDevil/Analyzer/AnalyzerEngine.cs`
  - add `AnalyzeAsync(...)` mirroring `Analyze(...)` plus `CancellationToken`; `await recognizer.AnalyzeAsync(...)` per recognizer (sequential), then the identical enhance -> dedup -> threshold -> allow-list steps.
  - factor the shared post-processing (`EnhanceUsingContext` -> `RemoveDuplicates` -> `RemoveLowScores` -> `RemoveAllowList` + `AddRecognizerIdIfMissing`) into one private method so `Analyze` and `AnalyzeAsync` cannot drift.
- `src/TasmanianDevil/PiiEngine.cs`
  - add `DeidentifyAsync` / `AnonymizeAsync` / `AnalyzeAsync` overloads calling `AnalyzerEngine.AnalyzeAsync`.
  - add a way to include extra/async recognizers (e.g. `PiiOptions.ExtraRecognizers` or a `PiiEngine` ctor/`Create` overload) - closes the "no `RedactPii(recognizers)` hook" gap.
- `src/TasmanianDevil/PiiEntities.cs` - add `public const string Address = "ADDRESS";`.

Backward compatibility: sync API + all existing tests unchanged.

Tests (`tests/TasmanianDevil.Tests/`):
- sync-only `AnalyzeAsync` completes synchronously and equals `Analyze`.
- an async stub recognizer's spans merge through context/dedup/overlap.
- sync `Analyze` ignores an async (`RequiresAsync`) recognizer.

</details>

## Phase 2 - `TasmanianDevil.Remote` (new package, generic)

Repo: `~/dev/tasmaniandevil`. Brand-neutral, standalone, `HttpClient`-based. Mirror the
`IRemoteClassifier` / `HttpClassifier` split in `AgentGuard.RemoteClassifier`.

- `IPiiDetectionClient { ValueTask<IReadOnlyList<RemotePiiEntity>> DetectAsync(text, language, entities, ct); }`
- `HttpPiiDetectionClient : IPiiDetectionClient` - POSTs the wire contract, deserializes (System.Text.Json).
- `RemotePiiRecognizer : EntityRecognizer` - overrides `AnalyzeAsync`: call client, map `RemotePiiEntity{type,start,end,score}` -> `RecognizerResult`, fail-open (catch/log/`[]`), timeout via linked CTS. `Analyze` returns `[]`; `RequiresAsync => true`.
- `RemotePiiOptions` - endpoint, auth header name/value, timeout, fail-open|closed, category-map override, redacted-text passthrough toggle.

Wire contract (documented, stable; offsets are **UTF-16 code units** = .NET `string` indices):
```
POST {endpoint}
Request : { "text": "...", "language": "en", "entities": ["PERSON","ADDRESS"] }
Response: { "entities": [ { "type":"PERSON", "start":3, "end":11, "score":0.98 } ] }
```

## Phase 3 - `TasmanianDevil.Azure` (new package, REST)

Repo: `~/dev/tasmaniandevil`. Direct REST; no SDK dependency. Dependency-light (HttpClient + optional
token-provider delegate).

Endpoint: `POST {Endpoint}/language/:analyze-text?api-version=2024-11-01`
Auth: `Ocp-Apim-Subscription-Key` header (key) OR AAD bearer via the token delegate.

Request:
```json
{ "kind": "PiiEntityRecognition",
  "parameters": {
    "modelVersion": "latest",
    "domain": "phi" | "none",
    "piiCategories": ["Person","Address"],
    "stringIndexType": "Utf16CodeUnit",
    "loggingOptOut": true
  },
  "analysisInput": { "documents": [ { "id":"1", "language":"en", "text":"..." } ] } }
```
Response: `results.documents[].entities[] = { text, category, subcategory?, offset, length, confidenceScore }`
(+ `redactedText`).

**Correctness-critical:**
- `stringIndexType: "Utf16CodeUnit"` is **mandatory** - the service default is `TextElements_v8`, which
  misaligns offsets against C# strings (emoji/surrogates). `Start = offset`, `End = offset + length`.
- `loggingOptOut: true` by default - a PII tool must not let the service log the text.

Types: `AzurePiiClient` (REST + JSON), `AzurePiiRecognizer : EntityRecognizer` (map categories, fail-open),
`AzurePiiOptions` (endpoint, key|tokenProvider, api-version, `domain` PHI toggle, category filter,
confidence threshold, passthrough mode, loggingOptOut).

Default category map (overridable):

| Azure category | Canonical |
|---|---|
| Person | PERSON |
| Address | ADDRESS |
| PhoneNumber | PHONE_NUMBER |
| Email | EMAIL_ADDRESS |
| Organization | ORGANIZATION |
| DateTime | DATE_TIME |
| CreditCardNumber | CREDIT_CARD |
| USSocialSecurityNumber | US_SSN |
| IPAddress | IP_ADDRESS |
| IBAN | IBAN_CODE |
| URL | URL |

Tests: parse the exact sample response from the Azure how-to page; category map; `Utf16CodeUnit` /
`loggingOptOut` / `domain` serialization; fail-open. Gated E2E behind `AZURE_LANGUAGE_ENDPOINT` /
`AZURE_LANGUAGE_KEY`.

## Phase 4 - AgentGuard glue

Repo: `~/dev/AgentGuard`.

- `AgentGuard.Pii` (existing)
  - `PiiRule.EvaluateAsync`: switch `_analyzer.Analyze(...)` -> `await _analyzer.AnalyzeAsync(...)`
    (zero-cost `ValueTask` fast-path when no async recognizer -> offline unaffected). This is the only
    change needed here; it requires the AgentGuard-referenced `TasmanianDevil` package to include Phase 1
    (pack tasmaniandevil to `~/dev/.local-nuget` and refresh first - see the cross-repo note below).
- `AgentGuard.RemotePii` (**new package** - keeps the HTTP/remote concern out of the lean `AgentGuard.Pii`,
  mirroring the opt-in posture of `AgentGuard.Onnx`)
  - references `AgentGuard.Pii` + `TasmanianDevil.Remote`.
  - `.RedactPiiWithRemote(RemotePiiOptions | IPiiDetectionClient, PiiOptions?)` - build registry +
    `AddRecognizer(new RemotePiiRecognizer(...))` + `new PiiRule(options, analyzer: engine)`, mirroring
    `RedactPiiWithNer` in `AgentGuard.Onnx`.
- `AgentGuard.Azure` (existing)
  - references `TasmanianDevil.Azure`.
  - `.RedactPiiWithAzure(endpoint, credential, AzurePiiOptions?, PiiOptions?)` - same pattern; AAD via
    `Azure.Identity` here (concrete `DefaultAzureCredential`), passed to `TasmanianDevil.Azure` as the
    token-provider delegate.

Regression test: offline `PiiRule` still works now that it awaits `AnalyzeAsync`.

## Phase 5 - Hosting / config

`AgentGuard.Hosting`: add `RemotePii` / `AzurePii` `RuleConfiguration` types + `appsettings.json` binding
(endpoint, key/AAD, categories, domain, fail-open), register detectors, resolve into the pipeline. Can
land as a fast-follow after Phases 1-4.

## Cross-cutting

- **Fail-open by default** (recognizer level): remote down/timeout -> local-only results still redact
  structured PII (you lose names/addresses, not everything). Configurable fail-closed.
- **Privacy (loud):** remote PII sends raw text off-box - inverting the offline promise. Prominent doc
  warning; Azure `loggingOptOut: true` default; explicit note in builder XML docs.
- **Offsets:** UTF-16 everywhere; dedicated emoji/surrogate test.
- **Latency/streaming:** one round-trip per evaluation; per-chunk streaming is chatty (note it).

## Samples & docs

- `samples/RemotePii` (AgentGuard): in-proc stub implementing the wire contract, wrapping
  TasmanianDevil + GLiNER as the "remote"; shows names/addresses redacted remotely while structured PII
  stays local. Azure section gated on env.
- TasmanianDevil README / PiiShowcase: a `DeidentifyAsync` + remote-recognizer section.
- `docs/remote-pii.md`: wire contract, sidecar recipe, Azure setup, privacy note.
- Update both `CLAUDE.md` files, TasmanianDevil `README.md`, and the websites. Version bump (0.11.0).

## Sequencing

1. Phase 1 (engine async) - the enabler; standalone-valuable; fully testable alone.
2. Phase 2 (`TasmanianDevil.Remote`) + AgentGuard `.RedactPiiWithRemote` + sample.
3. Phase 3 (`TasmanianDevil.Azure`) + AgentGuard `.RedactPiiWithAzure` + gated E2E.
4. Phase 5 (Hosting) + docs / website.

## Cross-repo dev reminder

Local NuGet feed at `~/dev/.local-nuget`: `dotnet pack -o ~/dev/.local-nuget`, then clear
`~/.nuget/packages/{tasmaniandevil,tasmaniandevil.onnx,tasmaniandevil.azure,tasmaniandevil.remote}` to
refresh the same version. Build/test each repo with `./eng/build.sh`. Follow both `CLAUDE.md` conventions
(using-imports only, file-scoped namespaces, `ValueTask`, lowercase comments, `ShouldX_WhenY` tests,
FluentAssertions).
