# Start prompt - Remote PII implementation (Phases 2-5)

Phase 1 (the async engine spine in TasmanianDevil) is **done**. Paste the block below into a fresh
session to continue with Phases 2-5.

---

We're continuing the "remote PII detection" feature. Phase 1 is done. The full design is in
`~/dev/AgentGuard/docs/remote-pii-plan.md` - read it first; it is the source of truth. Repos:
`~/dev/tasmaniandevil` (engine + two new detector packages) and `~/dev/AgentGuard` (guardrail glue +
samples). Read each repo's `CLAUDE.md` and follow its conventions (using-imports only, file-scoped
namespaces, `ValueTask` over `Task`, XML docs on public APIs, lowercase comments starting with a
lowercase letter, `ShouldX_WhenY` test names, FluentAssertions; `TreatWarningsAsErrors` is on).

**Confirmed Phase 1 surface to build on** (already landed in tasmaniandevil):
- `EntityRecognizer`: `virtual bool RequiresAsync => false`;
  `virtual ValueTask<IReadOnlyList<RecognizerResult>> AnalyzeAsync(string text, IReadOnlyList<string> entities, CancellationToken ct = default)` (default wraps sync `Analyze`).
- `AnalyzerEngine.AnalyzeAsync(text, language, entities, scoreThreshold, allowList, allowListMatch, context, ct)`.
- `PiiEngine`: `AnalyzeAsync`/`AnonymizeAsync`/`DeidentifyAsync`; extra recognizers via the ctor param
  `PiiEngine(PiiOptions?, AnalyzerEngine?, AnonymizerEngine?, IEnumerable<EntityRecognizer>? extraRecognizers)`.
- `PiiEntities.Address = "ADDRESS"`.

A remote/Azure recognizer subclasses `EntityRecognizer`, overrides `AnalyzeAsync`, sets
`RequiresAsync => true`, returns `[]` from sync `Analyze`, catches its own errors (fail-open -> `[]`,
configurable), and declares `SupportedEntities` + `SupportedLanguage` (they drive registry selection and
the context enhancer).

Do the phases **one at a time, building + testing + summarizing + pausing for review** between each. Add
every new `.csproj` to the repo's `.slnx` and any package versions to `Directory.Packages.props`.

**Phase 2 - `TasmanianDevil.Remote`** (tasmaniandevil): new package (references `TasmanianDevil`,
HttpClient-based). Files: `IPiiDetectionClient`, `RemotePiiEntity` (record: Type/Start/End/Score),
`HttpPiiDetectionClient` (System.Text.Json), `RemotePiiRecognizer : EntityRecognizer`, `RemotePiiOptions`
(endpoint, auth header, timeout, fail-open|closed, supported-entities set, category-map override,
redacted-text passthrough toggle). Wire contract (offsets are UTF-16 code units = .NET string indices):
`POST {endpoint}` request `{ "text","language","entities" }` -> response
`{ "entities":[{ "type","start","end","score" }] }`. Tests (`tests/TasmanianDevil.Remote.Tests`): mock
`IPiiDetectionClient` for mapping, fail-open on throw, timeout, emoji/surrogate offset alignment, and
overlap-merge through `AnalyzerEngine.AnalyzeAsync`. Build `./eng/build.sh`, summarize, **pause**.

**Phase 3 - `TasmanianDevil.Azure`** (tasmaniandevil): new package, direct REST, dependency-light
(HttpClient + optional token-provider delegate `Func<CancellationToken, ValueTask<string>>`, no
`Azure.Identity`). `POST {Endpoint}/language/:analyze-text?api-version=2024-11-01`, header
`Ocp-Apim-Subscription-Key` or AAD bearer. Request `parameters` must set `stringIndexType:"Utf16CodeUnit"`
and `loggingOptOut:true` by default; support `domain:"phi"|"none"`, `piiCategories`, confidence threshold.
Map Azure categories -> canonical (table in the plan; `Person->PERSON`, `Address->ADDRESS`, etc.).
Fail-open. Files: `AzurePiiClient`, `AzurePiiOptions`, `AzurePiiRecognizer : EntityRecognizer`,
`AzurePiiCategoryMap`, DTOs. Tests: parse the exact sample response from the plan, category mapping,
`Utf16CodeUnit`/`loggingOptOut`/`domain` serialization, fail-open; gated E2E behind
`AZURE_LANGUAGE_ENDPOINT`/`AZURE_LANGUAGE_KEY`. Build, summarize, **pause**.

**Cross-repo refresh before Phase 4:** `cd ~/dev/tasmaniandevil && dotnet pack -o ~/dev/.local-nuget`,
then clear `~/.nuget/packages/tasmaniandevil*` so AgentGuard picks up Phase 1's `AnalyzeAsync` and the new
`TasmanianDevil.Remote`/`TasmanianDevil.Azure` packages.

**Phase 4 - AgentGuard glue** (AgentGuard): (a) `AgentGuard.Pii/PiiRule.EvaluateAsync` -> `await
_analyzer.AnalyzeAsync(...)` (offline unaffected via the ValueTask fast-path); (b) new package
`AgentGuard.RemotePii` (references `AgentGuard.Pii` + `TasmanianDevil.Remote`) with
`.RedactPiiWithRemote(...)`; (c) `AgentGuard.Azure` gains `.RedactPiiWithAzure(...)` over
`TasmanianDevil.Azure` (AAD via `Azure.Identity` -> token delegate). Both builders mirror
`RedactPiiWithNer` in `AgentGuard.Onnx` (build registry + `AddRecognizer` + `new PiiRule(options,
analyzer: engine)`). Regression: offline `PiiRule` still redacts. Add `samples/RemotePii` (in-proc stub
implementing the wire contract, wrapping TasmanianDevil+GLiNER as the "remote"; Azure section gated on
env). Build `./eng/build.sh`, summarize, **pause**.

**Phase 5 - Hosting/config** (AgentGuard): `AgentGuard.Hosting` `RemotePii`/`AzurePii`
`RuleConfiguration` types + `appsettings.json` binding + DI registration. Then docs: `docs/remote-pii.md`
(wire contract, sidecar recipe, Azure setup, loud privacy note that raw text leaves the process), update
both `CLAUDE.md` files, TasmanianDevil `README.md`, websites; version bump 0.11.0.

Start with Phase 2. Don't run ahead of the review gates.

---

## Notes for the driver (not part of the paste)

- Full signatures, the Azure request/response sample, and the category-map table are all in
  `remote-pii-plan.md`.
- Package placement decision (refined from the original plan): remote glue is a **new `AgentGuard.RemotePii`
  package**, not added to `AgentGuard.Pii`, to keep the offline package lean.
