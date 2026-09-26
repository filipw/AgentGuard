# AgentGuard

**Declarative guardrails and safety controls for .NET AI agents**

[![NuGet](https://img.shields.io/nuget/v/AgentGuard.svg)](https://www.nuget.org/packages/AgentGuard)
[![Build](https://github.com/filipw/AgentGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/filipw/AgentGuard/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

What [NeMo Guardrails](https://github.com/NVIDIA/NeMo-Guardrails) and [Guardrails AI](https://github.com/guardrails-ai/guardrails) do for Python, **AgentGuard** does for .NET - with the fluent APIs, composable rules, and type safety that .NET developers expect.

---

## Why AgentGuard?

Every AI agent needs the same safety guardrails: PII detection, prompt injection blocking, topic enforcement, token limits, output validation. AgentGuard provides all of this as composable, testable, declarative rules.

The core engine is **framework-agnostic** - use it standalone, with Microsoft Agent Framework, Semantic Kernel, or any other .NET AI stack. Framework-specific adapters (like `AgentGuard.AgentFramework` for MAF) wire guardrails into the host's middleware pipeline.

```csharp
// Get started with sensible defaults - fully offline, no configuration needed
using AgentGuard.Onnx;

var policy = new GuardrailPolicyBuilder()
    .UseDefaults()    // normalization + regex + Defender ML + PII + secrets + tool guardrails
    .Build();

var pipeline = new GuardrailPipeline(policy, logger);
var result = await pipeline.RunAsync(new GuardrailContext { Text = userInput, Phase = GuardrailPhase.Input });

if (result.IsBlocked)
    Console.WriteLine($"Blocked: {result.BlockingResult!.Reason}");
```

```csharp
// Or pick and choose individual rules
var policy = new GuardrailPolicyBuilder()
    .NormalizeInput()              // decode base64/hex/unicode evasion tricks
    .GuardRetrieval()              // filter poisoned RAG chunks
    .BlockPromptInjection()        // regex-based injection detection
    .RedactPii(new PiiOptions { Entities = ["EMAIL_ADDRESS", "PHONE_NUMBER", "US_SSN"] })
    .DetectSecrets()               // block API keys, tokens, connection strings
    .EnforceTopicBoundaryWithLlm(chatClient, "customer-support", "billing", "returns")
    .LimitInputTokens(4000)
    .GuardToolCalls()              // inspect tool call arguments for injection
    .GuardToolResults()            // detect indirect injection in tool results
    .Build();
```

```csharp
// Wrap any IChatClient - one line, transparent guardrails
using AgentGuard.Core.ChatClient;
using AgentGuard.Onnx;

var guardedClient = chatClient.UseAgentGuard(g => g.UseDefaults());

// Use exactly like a normal IChatClient
var response = await guardedClient.GetResponseAsync(conversationHistory);
```

```csharp
// Plug into Microsoft Agent Framework
using AgentGuard.AgentFramework;
using AgentGuard.Onnx;

var guardedAgent = agent
    .AsBuilder()
    .UseAgentGuard(g => g.UseDefaults())
    .Build();
```

## Features

### Regex-based rules (fast, zero-cost, offline)

- **Input normalization** - decodes evasion encodings (base64, hex, reversed text, Unicode homoglyphs, leetspeak) and strips invisible characters (zero-width characters and Unicode tag characters, whose hidden text is added as a decoded view) before downstream rules evaluate the text, catching attacks hidden via encoding tricks
- **Prompt injection detection** - blocks jailbreak attempts, system prompt extraction, role-play attacks, end sequence injection, variable expansion, framing attacks, and rule addition with configurable sensitivity levels (Low/Medium/High). Patterns based on the [Arcanum Prompt Injection Taxonomy](https://github.com/Arcanum-Sec/arc_pi_taxonomy)
- **PII redaction** - a complete offline detection and de-identification engine inspired by the architecture of [Microsoft Presidio](https://github.com/microsoft/presidio) (MIT), with validated regex + checksum recognizers, confidence scoring, overlap resolution, lemma-aware context boosting, and anonymization operators (replace/redact/mask/hash/encrypt/keep/custom). Generic entities (email, phone via libphonenumber, credit card/Luhn, IBAN, crypto, IP, URL, MAC) plus a complete US pack are always on; opt-in country packs for the UK, Germany, India, Italy, Spain and the Netherlands add national IDs, tax numbers, passports, driving licences and more via `Countries`. Reversible de-identification (`DeanonymizerEngine` restores AES-encrypted spans), structured-data redaction (`StructuredEngine` for JSON by key path and CSV by column inference), and a batch API (`BatchAnalyzerEngine`/`BatchAnonymizerEngine`) are all built in and fully offline. An optional offline ONNX add-on, `RedactPiiWithNer()` (`AgentGuard.Onnx`, separate [GLiNER](https://huggingface.co/filip-w/gliner-multi-pii-onnx) download, see [`eng/MODELS.md`](eng/MODELS.md)), adds multilingual named-entity detection - `PERSON`, `LOCATION`, `ORGANIZATION`, `DATE_TIME` - that regex can't catch, resolved in the same order-20 pass. See [`samples/AgentFrameworkPii`](samples/AgentFrameworkPii) for an end-to-end tour
- **Token limits** - enforces input/output token budgets using `Microsoft.ML.Tokenizers` (cl100k_base by default, o200k_base and OpenAI model names too) with configurable overflow strategies (Reject/Truncate/Warn)
- **Secrets detection** - detects API keys (AWS, GitHub including fine-grained tokens, Azure, Slack), quoted secret fields in JSON and config, JWT tokens, private keys (PEM, PGP and SSH2, matched and redacted as the whole block), connection strings and URIs with a password, bearer tokens. Block or redact actions (redaction replaces only the secret value) with custom patterns and optional charset-aware entropy detection
- **Content safety** - severity-based filtering via pluggable `IContentSafetyClassifier` (Azure AI Content Safety adapter included). Detects harmful content (hate, violence, self-harm, sexual) - a complementary layer to prompt injection detection, not a substitute for it
- **Offline multilingual content safety** - the [Opir](https://huggingface.co/filip-w/opir-multilang-onnx) mDeBERTa-v3 classifier (GLiClass, Apache 2.0) scores toxicity, hate speech, violence, sexual content, self-harm, and harassment in any language, fully offline. A local alternative to the cloud Azure Content Safety adapter for non-English text, when a per-call cloud API isn't an option (offline/sovereign deployments, PII constraints). Order 50, `AgentGuard.Onnx`, separate download (see [`eng/MODELS.md`](eng/MODELS.md)). See [docs/rules-reference.md](docs/rules-reference.md#content-safety-onnx---opir-offline-multilingual)
- **Azure Prompt Shields** - dedicated prompt injection detection via Azure AI Content Safety's Prompt Shield API (`text:shieldPrompt`). Detects user prompt attacks (jailbreaks, role-play, encoding attacks) and document attacks (indirect injection in grounded content). Complements the local multi-head Defender model with a cloud-based signal. Order 14. Install via `AgentGuard.Azure` package
- **Azure Protected Material detection** - detects copyrighted text (lyrics, articles, recipes) and code from GitHub repositories in LLM-generated output via `text:detectProtectedMaterial` and `text:detectProtectedMaterialForCode`. Code detection returns license info and source URLs. No C# SDK exists for these APIs - AgentGuard provides the only .NET client. Output phase (order 76), supports Block/Warn actions. Install via `AgentGuard.Azure` package

### RAG & Agentic guardrails (zero-cost, offline)

- **Retrieval guardrails** - filters retrieved chunks before they reach the LLM context. Detects prompt injection, secrets, and PII in knowledge base content. Supports relevance score filtering, max chunk limits, remove/sanitize actions, and custom filters. Integrates with MAF via `RetrievalGuardrailContextProvider`
- **Tool call guardrails** - inspects agent tool call arguments for SQL injection, code injection, path traversal, command injection, SSRF, template injection, and XSS. Per-tool and per-argument allowlists for tools that legitimately accept code/SQL. In MAF, each call's arguments are checked before the tool runs, so a blocked call is never executed; the `IChatClient` decorator checks the tool calls in each response (see [Tool Call Guardrails](#tool-call-guardrails))
- **Tool result guardrails** - detects indirect prompt injection hidden in tool call results (emails, documents, API responses). Three-tier risk-based detection with tool-specific risk profiles (email=high, docs=medium, calculator=low). Supports block or sanitize actions (sanitize removes each injection from the start of its line to the end of its paragraph), stripping of invisible Unicode characters including tag characters, detection of injections hidden in base64, hex or percent-encoded runs, and custom patterns. In MAF, each tool result is checked before the model sees it. Inspired by [StackOneHQ/defender](https://github.com/StackOneHQ/defender)

### ONNX ML-based rules (fast, accurate, offline)

- **StackOne Defender prompt injection detection** - uses the [StackOne Defender](https://github.com/StackOneHQ/defender) fine-tuned multi-head MiniLM-L6 ONNX model (minilm-multihead-v5, ~22 MB, bundled in NuGet) for ML-based classification. Calibrated dual-head decision (`main >= threshold AND aux < veto`) keeps imperative-but-benign requests like "show me my orders" from being flagged. ~8 ms inference, fully offline. **No download required** - the model ships in the Kyoto NuGet package that `AgentGuard.Onnx` depends on, so installing `AgentGuard.Onnx` (or the umbrella `AgentGuard` package) brings it. Order 11 (default). Also supports two optional DeBERTa v3 rules at order 12 (separate download): a generic bring-your-own-model rule (fetched via the Kyoto bootstrap) and **PIGuard** (see [`eng/MODELS.md`](eng/MODELS.md)), the latter far stronger on indirect / code-style injection (see [docs/rules-reference.md](docs/rules-reference.md#prompt-injection-detection-onnx---piguard))
- **Long input** - every ONNX rule (Defender, DeBERTa, PIGuard, Opir) classifies text that fits one window in a single call and splits longer text into overlapping windows (`WindowSize`, `WindowOverlap`, `MaxWindows` options); the input is blocked if any window is. Input that needs more than `MaxWindows` windows (0 = no limit) is blocked with Medium severity and `inputTooLong` metadata. Because every passage is classified, Defender blocks long technical or instructional text more often than short prompts

### Remote ML classifier (SOTA models via HTTP)

- **Remote prompt injection detection** - calls external model servers (Ollama, vLLM, HuggingFace TGI, custom FastAPI endpoints) for ML-based classification. Designed for SOTA models like [Sentinel-v2](https://huggingface.co/rogue-security/prompt-injection-jailbreak-sentinel-v2) (Qwen3-0.6B, F1 ~0.957, 32K context). Lightweight - no native ML dependencies, just `HttpClient`. An optional API key is sent as a Bearer token with each request, so classifiers with different keys can share one `HttpClient`. Pluggable `IRemoteClassifier` abstraction. Order 13, fails open by default. Install via `AgentGuard.RemoteClassifier` package.

### LLM-based rules (accurate, pluggable via `IChatClient`)

For teams that need higher accuracy than regex, AgentGuard provides LLM-as-judge guardrail rules that work with any `IChatClient` (Azure OpenAI, Ollama, local models, etc.):

- **LLM prompt injection detection** - catches sophisticated attacks that regex misses: narrative smuggling, meta-prompting, cognitive overload, multi-chain attacks, and more. Prompt templates cover all 12 attack technique families and 20 evasion methods from the [Arcanum PI Taxonomy](https://github.com/Arcanum-Sec/arc_pi_taxonomy). Returns structured threat classification metadata (technique, intent, evasion, confidence) for operational telemetry
- **LLM PII detection & redaction** - catches unstructured PII like full names, physical addresses, and contextual identifiers that regex can't find. Supports block or redact (the default) modes
- **LLM topic boundary enforcement** - semantic topic classification that understands intent, not just keywords
- **LLM output policy enforcement** - checks if agent responses violate custom policy constraints (e.g. "never recommend competitors", "always include a disclaimer"). Configurable policy description with block or warn modes
- **LLM groundedness checking** - detects hallucinated facts and claims not supported by the conversation context. Uses conversation history for grounding evaluation
- **LLM copyright detection** - catches verbatim reproduction of copyrighted material (song lyrics, book passages, articles, restrictively-licensed code). Kill switch for copyright violations

```csharp
using AgentGuard.Onnx;
using AgentGuard.RemoteClassifier;
using AgentGuard.Azure.PromptShield;

// Five-tier prompt injection detection: Regex → Defender → Remote ML → Prompt Shield → LLM
// (the optional DeBERTa / PIGuard classifiers slot in at order 12)
var policy = new GuardrailPolicyBuilder()
    .BlockPromptInjection()                              // tier 1: fast regex (order 10)
    .BlockPromptInjectionWithDefender()                   // tier 2: Defender ML (order 11, bundled)
    .BlockPromptInjectionWithRemoteClassifier(            // tier 3: remote ML (order 13)
        "http://localhost:8000/classify", modelName: "sentinel-v2")
    .BlockPromptInjectionWithAzurePromptShield(           // tier 4: Azure Prompt Shield (order 14)
        endpoint, apiKey)
    .BlockPromptInjectionWithLlm(chatClient)             // tier 5: LLM judge (order 15)
    .DetectPIIWithLlm(chatClient, new() { Action = PiiAction.Redact })
    .EnforceTopicBoundaryWithLlm(chatClient, "billing", "payments")
    .LimitInputTokens(4000)
    .Build();
```

All LLM rules ship with built-in prompt templates and support custom system prompt overrides. They fail open on LLM errors - your agent keeps working even if the classifier is down.

### Streaming support

AgentGuard works with both `RunAsync` and `RunStreamingAsync` when used with MAF, and with both `GetResponseAsync` and `GetStreamingResponseAsync` in the `IChatClient` decorator. Two streaming modes are available:

- **Buffer-then-release** (default) - buffers all output chunks and guards the buffered response exactly as the non-streaming path does (each assistant message, its reasoning, and the tool calls and tool results the stream carried), then yields the original chunks if nothing changed. When a rule rewrites the response, the updates are rebuilt from the guarded messages, keeping tool calls, usage and ids; a block becomes one update carrying the violation message.
- **Progressive with retraction** - answer tokens stream through to the user immediately while guardrails evaluate progressively. On violation, retraction/replacement events are emitted so the UI can hide/replace content already shown. Everything else the stream carries (tool calls and results, reasoning, usage, finish reason) is held back until the stream ends, checked there (tool calls and results by the tool rules, reasoning like answer text), and then released - or dropped if the response ends blocked. Follows the Azure OpenAI content filter pattern.

```csharp
// Enable progressive streaming
var policy = new GuardrailPolicyBuilder()
    .RedactPii()
    .CheckGroundedness(chatClient)
    .UseProgressiveStreaming()  // tokens flow immediately, retract on violation
    .Build();
```

Fast rules (regex, local) evaluate on every check cycle. Expensive LLM rules only evaluate at the end. Rules can declare their preference via `IStreamingGuardrailRule`. A rule gated with `.When()` / `.Unless()` keeps the mode of the rule it wraps.

### Additional features

- **Output validation** - fluent predicate-based assertions on agent responses
- **Dynamic rule enabling** - gate any rule per request with `.When(predicate)` / `.Unless(predicate)`. The predicate sees the `GuardrailContext` and can capture ambient services (e.g. `IHttpContextAccessor`) to enable/disable a rule based on `ClaimsPrincipal`, tenant, feature flag, or detected language - for instance, running the English-centric Defender classifier at a higher threshold for non-English users instead of accepting its false positives. A gated rule keeps its type-based behavior (an LLM judge stays final-only in progressive streaming, a gated tool rule still wires the MAF tool middleware), and `rule.Unwrap()` returns the rule behind a gate
- **Custom rules** - implement `IGuardrailRule` to add your own checks with full access to the conversation context
- **Framework-agnostic core** - use the rules engine standalone or plug into MAF, Semantic Kernel, or any framework
- **Fully testable** - every rule is a pure function; mock the pipeline, assert the behavior
- **Configuration-driven** - define policies in `appsettings.json`: most built-in rule types, named policies, DI resolution for LLM/cloud rules, and `IGuardrailRuleFactory` for the Azure / remote PII detectors and rule types of your own
- **Offline-first** - works without any cloud services; optionally upgrade to Azure AI Content Safety or LLM-based rules for production accuracy

### Observability (OpenTelemetry)

AgentGuard emits OpenTelemetry-compatible **spans** and **metrics** for every pipeline run, rule evaluation, re-ask attempt, and streaming retraction. All instrumentation uses `System.Diagnostics.Activity` and `System.Diagnostics.Metrics` - no SDK dependency in core packages.

```csharp
// With AgentGuard.Hosting - one-liner registration
using AgentGuard.Hosting;

builder.Services.AddOpenTelemetry()
    .WithTracing(t => t.AddAgentGuardInstrumentation())
    .WithMetrics(m => m.AddAgentGuardInstrumentation());
```

```csharp
// Or register manually - works without AgentGuard.Hosting
builder.Services.AddOpenTelemetry()
    .WithTracing(t => t.AddSource("AgentGuard"))
    .WithMetrics(m => m.AddMeter("AgentGuard"));
```

**Spans** trace every pipeline run (`agentguard.pipeline.run`), individual rule evaluation (`agentguard.rule.evaluate {name}`), re-ask loops (`agentguard.pipeline.reask`), streaming evaluations (`agentguard.streaming.pipeline`), MAF middleware entry points (`agentguard.middleware.input`, `agentguard.middleware.output`, `agentguard.middleware.streaming`), and workflow executors (`agentguard.executor.guard`). Each span includes tags for policy name, phase, outcome, and rule-specific metadata.

**Metrics** include counters for pipeline evaluations, rule evaluations, blocks, re-ask attempts, text modifications, and streaming retractions - plus duration histograms for both pipeline and per-rule execution.

**Sensitive data** (input/output text) is **not captured by default**. Opt in via:
```csharp
AgentGuardTelemetry.EnableSensitiveData = true;
// or set environment variable: AGENTGUARD_CAPTURE_CONTENT=true
```

See the [Observability docs](docs/observability.md) for the full span and metric reference.

### Tamper-evident decision ledger

For compliance and forensics, AgentGuard can keep a **tamper-evident audit trail** of pipeline decisions. Each decision (what policy was active, what was requested, and why it was allowed/blocked/modified) is stamped into a SHA-256 **hash chain** - every entry hashes its own fields plus the previous entry's hash, so any retroactive edit breaks the chain and is caught by `Verify()`. The ledger types live in `AgentGuard.Core.Ledger` and are dependency-free (`System.Security.Cryptography` + `System.Text.Json`); one entry is emitted per pipeline evaluation, so every re-ask attempt is independently auditable.

```csharp
// Standalone
using AgentGuard.Core.Ledger;

var ledger = new HashChainLedger();
var pipeline = new GuardrailPipeline(policy, logger, ledger);

// ... run the pipeline ...
bool intact = ledger.Verify();      // false if any recorded decision was tampered with
string auditJson = ledger.Export(); // full chain as JSON
```

```csharp
// With AgentGuard.Hosting - registered as a singleton in DI
builder.Services.AddAgentGuard(options =>
{
    options.DefaultPolicy(p => p.BlockPromptInjection().RedactPii());
    options.UseDecisionLedger();                          // in-memory hash chain
    // options.UseDecisionLedger("audit/decisions.jsonl"); // also mirror to an append-only JSONL file
});
```

The pipeline `AddAgentGuard` registers and the MAF agent middleware resolve the ledger from DI (the middleware from the service provider the agent is built with). The `IChatClient` decorator and workflow executors build their own pipelines, so pass the ledger to them: `chatClient.UseAgentGuard(configure, ledger: ledger)` and `GuardedExecutorOptions.Ledger`.

Editing an entry or removing one from the middle of the chain is caught by `Verify()`; removing
entries from the *end* is not, since a hash chain carries no record of how long it should be. The
in-memory chain is unbounded unless you pass `maxInMemoryEntries`.

The ledger is **hash-only by default** (records `InputHash`/`OutputHash`, not raw content); raw `Input`/`Output` are captured only when content capture is enabled via the same `AgentGuardTelemetry.EnableSensitiveData` flag (env `AGENTGUARD_CAPTURE_CONTENT=true`). See the [Observability docs](docs/observability.md#tamper-evident-decision-ledger) for details.

## Packages

| Package | Description | NuGet |
|---------|-------------|-------|
| `AgentGuard` | **All-in-one package**: core rules engine, bundled Defender multi-head ONNX model, offline PII engine | [![NuGet](https://img.shields.io/nuget/v/AgentGuard.svg)](https://www.nuget.org/packages/AgentGuard) |
| `AgentGuard.Core` | Framework-agnostic core only: abstractions, rules engine, fluent builder, and the built-in rule set | [![NuGet](https://img.shields.io/nuget/v/AgentGuard.Core.svg)](https://www.nuget.org/packages/AgentGuard.Core) |
| `AgentGuard.AgentFramework` | Microsoft Agent Framework adapter: `UseAgentGuard()` middleware + workflow guardrails via `.WithGuardrails()` | [![NuGet](https://img.shields.io/nuget/v/AgentGuard.AgentFramework.svg)](https://www.nuget.org/packages/AgentGuard.AgentFramework) |
| `AgentGuard.Onnx` | ONNX-based ML classifiers - bundled StackOne Defender multi-head model (minilm-multihead-v5, shipped in its Kyoto dependency) + optional DeBERTa v3 and PIGuard injection classifiers + Opir multilingual content-safety classifier + GLiNER NER for PII (`RedactPiiWithNer()`) | [![NuGet](https://img.shields.io/nuget/v/AgentGuard.Onnx.svg)](https://www.nuget.org/packages/AgentGuard.Onnx) |
| `AgentGuard.RemoteClassifier` | Remote ML classifier via HTTP - call Sentinel-v2, Ollama, vLLM, or custom endpoints | [![NuGet](https://img.shields.io/nuget/v/AgentGuard.RemoteClassifier.svg)](https://www.nuget.org/packages/AgentGuard.RemoteClassifier) |
| `AgentGuard.Pii` | Offline PII detection and de-identification over the TasmanianDevil engine: the order-20 `PiiRule` and `.RedactPii()` | [![NuGet](https://img.shields.io/nuget/v/AgentGuard.Pii.svg)](https://www.nuget.org/packages/AgentGuard.Pii) |
| `AgentGuard.RemotePii` | Out-of-process PII detection over a generic HTTP contract - `.RedactPiiWithRemote()` | [![NuGet](https://img.shields.io/nuget/v/AgentGuard.RemotePii.svg)](https://www.nuget.org/packages/AgentGuard.RemotePii) |
| `AgentGuard.Azure` | Azure AI Content Safety: Prompt Shields (injection detection) + protected material detection (text & code with license citations) + text analysis (harmful content) + blocklists, plus Azure AI Language PII entity recognition (native Person/Address) | [![NuGet](https://img.shields.io/nuget/v/AgentGuard.Azure.svg)](https://www.nuget.org/packages/AgentGuard.Azure) |
| `AgentGuard.Hosting` | DI registration, named policy factory, `appsettings.json` config binding | [![NuGet](https://img.shields.io/nuget/v/AgentGuard.Hosting.svg)](https://www.nuget.org/packages/AgentGuard.Hosting) |

## Quick Start

### Install

```bash
dotnet add package AgentGuard --prerelease
```

### Basic Usage (standalone, no framework dependency)

```csharp
using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Builders;
using AgentGuard.Core.Guardrails;
using AgentGuard.Pii;
using Microsoft.Extensions.Logging.Abstractions;

var policy = new GuardrailPolicyBuilder()
    .BlockPromptInjection()
    .RedactPii()
    .EnforceTopicBoundaryWithLlm(chatClient, "customer-support")
    .OnViolation(v => v.RejectWithMessage("I can only help with customer support topics."))
    .Build();

var pipeline = new GuardrailPipeline(policy, NullLogger<GuardrailPipeline>.Instance);

var ctx = new GuardrailContext
{
    Text = userInput,
    Phase = GuardrailPhase.Input,
    Messages = conversationHistory  // IReadOnlyList<ChatMessage> - optional, enables history-aware rules
};
var result = await pipeline.RunAsync(ctx);

if (result.IsBlocked)
    Console.WriteLine($"Blocked: {result.BlockingResult!.Reason}");
else if (result.WasModified)
    Console.WriteLine($"Modified: {result.FinalText}");
```

### With IChatClient Decorator

```csharp
using AgentGuard.Core.ChatClient;
using AgentGuard.Pii;

// Wrap any IChatClient - works with OpenAI, Azure OpenAI, Ollama, or any Microsoft.Extensions.AI client
var guardedClient = chatClient.UseAgentGuard(g => g
    .BlockPromptInjection()
    .RedactPii()
    .EnforceTopicBoundaryWithLlm(chatClient, "customer-support")
    .OnViolation(v => v.RejectWithMessage("I can only help with customer support topics."))
);

// Use it exactly like a normal IChatClient - guardrails run transparently
// Conversation history is automatically propagated to all rules
var response = await guardedClient.GetResponseAsync(conversationHistory);

// Streaming is also supported - input guardrails run before the stream starts
await foreach (var update in guardedClient.GetStreamingResponseAsync(conversationHistory))
    Console.Write(update.Text);
```

Callers usually resend the whole conversation, so input guardrails run on every user message in the request, not only the last one. The newest user message is always evaluated. An earlier one reuses the verdict already reached for identical text (kept in a bounded cache) or, on a miss, is judged against the conversation as it stood at that point. An earlier user message the policy blocks is replaced, attachments included, with `ChatMessageGuard.RemovedMessagePlaceholder` (`[message removed by guardrail policy]`); only a block of the newest user message blocks the call.

Output guardrails evaluate each assistant message of the response on its own (streamed responses too), and the response's tool calls and tool results once, together with its final text. The reasoning of each assistant message (`TextReasoningContent`, which clients often display) goes through the output rules separately: a rewrite replaces the reasoning text and a block removes it, without blocking the answer. Encrypted reasoning (`ProtectedData`) is kept. A rewrite replaces only the text: images, attachments, tool calls and message and response metadata are kept. A successful [re-ask](docs/getting-started.md#re-ask--self-healing-experimental) replaces the blocked answer, and the reasoning behind it goes too.

### With Microsoft Agent Framework

```bash
dotnet add package AgentGuard.AgentFramework --prerelease
```

```csharp
using AgentGuard.AgentFramework;
using AgentGuard.Pii;

var guardedAgent = agent
    .AsBuilder()
    .UseAgentGuard(g => g
        .BlockPromptInjection()
        .RedactPii()
        .EnforceTopicBoundaryWithLlm(chatClient, "customer-support")
        .OnViolation(v => v.RejectWithMessage("I can only help with customer support topics."))
    )
    .Build();

// Use it exactly like a normal agent - guardrails are transparent
var response = await guardedAgent.RunAsync(messages, session, options);
```

The middleware guards messages the same way as the `IChatClient` decorator: every user message of the request on the way in, each assistant message of the response on the way out. When the agent invokes functions through a `FunctionInvokingChatClient` (as `ChatClientAgent` does), `GuardToolCalls()` checks tool calls before they run and `GuardToolResults()` checks tool results before the model sees them - see [Tool Call Guardrails](#tool-call-guardrails).

`ChatClientAgent` saves its response to the session's chat history before outer middleware sees it. When the session uses the default in-memory history provider, the middleware rewrites the stored response after an output block or rewrite, so the next turn replays what the caller received rather than the raw model output. It can't reach other history providers or service-side conversations (a `ConversationId`); where stored history must never hold unguarded output, also put `UseAgentGuard()` on the agent's `IChatClient`, which guards the response before the agent saves it.

#### Reversible PII redaction

`UsePiiReversibleRedaction` encrypts the PII in every text-bearing message of the request into opaque tokens before the inner agent and the model provider see it, and decrypts the tokens back to the original values in the response. The model reasons over placeholders while the user still sees the real values:

```csharp
var agent = innerAgent
    .AsBuilder()
    .UsePiiReversibleRedaction(key)   // AES key: 16, 24 or 32 bytes when UTF-8 encoded
    .Build();
```

Restoration is by exact token match, so it survives the model echoing a token anywhere in its answer, even glued to other characters; a token the model paraphrases or drops is not restored. Only tokens the middleware minted are restored: those of the current request and, when the run has an `AgentSession`, those of earlier turns in the same session (their ciphertext - never the values - is kept in the session's state, the most recent 4,096). A token from anywhere else - another session, a log, a tool result, or text a user pastes in - is left as is, even under the same key. Streaming output is restored the same way: text that could still be the start of a token is held back until it can be decided, so the streamed text matches the non-streamed text. `UsePiiReversibleRedaction(key, piiOptions)` takes the detection settings (entities, countries, language, threshold, allow-list) and always anonymizes with the reversible `encrypt` operator. To add remote or Azure detectors, or to share one engine across agents, pass a `PiiEngine` you own: `UsePiiReversibleRedaction(engine, key)`. Detection runs on the engine's async path, so remote and Azure detectors take part, and the anonymized text is always what reaches the model - spans an engine anonymizes with a non-reversible operator are removed but not restored.

When an agent also uses `UseAgentGuard(g => g.RedactPii())`, register `UsePiiReversibleRedaction` first so it is the outermost layer: the first registered middleware sees the request first, and the reversible layer has to encrypt the PII before the redaction rule would replace it.

### With LLM-based rules

```csharp
using Microsoft.Extensions.AI;
using AgentGuard.Core.Builders;
using AgentGuard.Core.Rules.LLM;
using OllamaSharp;

// Use any IChatClient - Azure OpenAI, OpenAI, Ollama (here via OllamaSharp), etc.
IChatClient classifier = new OllamaApiClient(new Uri("http://localhost:11434"), "llama3");

var policy = new GuardrailPolicyBuilder()
    .NormalizeInput()                                      // decode evasion encodings first
    .BlockPromptInjection()                                // regex: fast first pass
    .BlockPromptInjectionWithLlm(classifier)               // LLM: catches what regex misses
    .DetectPIIWithLlm(classifier)                          // LLM: catches names, addresses, etc.
    .EnforceTopicBoundaryWithLlm(classifier, "billing")    // LLM: semantic topic matching
    .LimitInputTokens(4000)
    .Build();
```

### With Dependency Injection (ASP.NET / Aspire)

```csharp
// the policy callbacks get the builder, not the service provider, so create the LLM client up front
IChatClient judge = new OpenAIClient(apiKey).GetChatClient("gpt-4o").AsIChatClient();

builder.Services.AddAgentGuard(options =>
{
    options.DefaultPolicy(policy => policy
        .BlockPromptInjection()
        .RedactPii()
        .LimitOutputTokens(2000));

    options.AddPolicy("strict", policy => policy
        .BlockPromptInjection(sensitivity: Sensitivity.High)
        .RedactPii()
        .EnforceTopicBoundaryWithLlm(judge, "billing"));
});
```

### With `appsettings.json` Configuration

Define guardrail policies entirely in configuration - no code changes needed to adjust rules:

```json
{
  "AgentGuard": {
    "DefaultPolicy": {
      "Rules": [
        { "Type": "PromptInjection", "Sensitivity": "High" },
        { "Type": "PiiRedaction", "Entities": ["EMAIL_ADDRESS", "PHONE_NUMBER", "US_SSN"] },
        { "Type": "TokenLimit", "MaxTokens": 4000 }
      ],
      "ViolationMessage": "Request blocked by safety policy."
    }
  }
}
```

```csharp
builder.Services.AddAgentGuard(builder.Configuration.GetSection("AgentGuard"));
```

See [Configuration docs](docs/configuration.md) for the full JSON schema and the rule types that can only be added in code.

### Workflow Guardrails

MAF workflows compose multiple `Executor` steps into a DAG. `AgentGuard.AgentFramework` includes workflow guardrails that let you wrap individual executors with guardrails at step boundaries using the `.WithGuardrails()` decorator:

```bash
dotnet add package AgentGuard.AgentFramework --prerelease
```

```csharp
using AgentGuard.AgentFramework.Workflows;

// Wrap a void executor with input guardrails
var guardedInput = myInputExecutor.WithGuardrails(b => b
    .NormalizeInput()
    .BlockPromptInjection(Sensitivity.High)
    .RedactPii());

// Wrap a typed executor with input + output guardrails
var guardedProcessor = myProcessorExecutor.WithGuardrails(b => b
    .RedactPii()
    .ValidateOutput(text => !text.Contains("internal-only"), "Leaked internal info"));

// Use in your workflow - GuardedExecutor is still an Executor
try
{
    await guardedInput.HandleAsync(userMessage, workflowContext);
    var result = await guardedProcessor.HandleAsync(input, workflowContext);
}
catch (GuardrailViolationException ex)
{
    Console.WriteLine($"Blocked at {ex.Phase} in '{ex.ExecutorId}': {ex.ViolationResult.Reason}");
}
```

`GuardedExecutor<TInput>` applies input guardrails before delegating to the inner executor. `GuardedExecutor<TInput, TOutput>` applies both input and output guardrails. If a guardrail blocks, a `GuardrailViolationException` is thrown (surfaced by MAF as `ExecutorFailedEvent`).

The guarded executor mirrors the inner executor's protocol and lifecycle (messages it sends and yields, its other handlers, initialization, checkpoints), so it can replace it anywhere in a workflow. Chat payloads - `ChatMessage`, message lists and `AgentResponse` - are guarded message by message like the agent middleware does, keeping attachments and metadata. Other types go through the `ITextExtractor` interface, which bridges typed workflow messages to string-based guardrail rules and can rebuild a message from rewritten text (`TryRebuild`). The built-in `DefaultTextExtractor` handles `string`, `ChatMessage`, `AgentResponse`, message collections and objects with a `Text` property.

### Tool Call Guardrails

When agents use tools, the LLM generates tool call arguments that are passed to external systems (databases, APIs, file systems). AgentGuard inspects these arguments for injection attacks:

```csharp
// With MAF - each call's arguments are checked before the tool runs; a blocked call is never executed
var agent = chatClient
    .AsAIAgent(instructions: "You are a helpful assistant",
        tools: [AIFunctionFactory.Create(QueryDatabase), AIFunctionFactory.Create(ReadFile)])
    .AsBuilder()
    .UseAgentGuard(g => g
        .BlockPromptInjection()
        .GuardToolCalls()  // inspects FunctionCallContent arguments automatically
    )
    .Build();

// Or standalone - pass tool calls via the context properties bag
var rule = new ToolCallGuardrailRule();
var toolCalls = new List<AgentToolCall>
{
    new() { ToolName = "query_db", Arguments = new Dictionary<string, string>
        { ["sql"] = "SELECT * FROM users UNION SELECT password FROM admin" } }
};
var ctx = new GuardrailContext { Text = "", Phase = GuardrailPhase.Output };
ctx.Properties["ToolCalls"] = (IReadOnlyList<AgentToolCall>)toolCalls;
var result = await rule.EvaluateAsync(ctx);
// result.IsBlocked == true, reason: "SQL UNION injection"
```

Detected injection categories: SQL injection, code injection (Python/JS/.NET/pickle), path traversal, command injection, SSRF, template injection (Jinja2/Handlebars), and XSS. Per-tool and per-argument allowlists let you exempt tools that legitimately accept code or SQL.

**In MAF**, when the policy contains `GuardToolCalls()` or `GuardToolResults()` (gated with `.When()` / `.Unless()` or not) and the agent invokes functions through a `FunctionInvokingChatClient`, a function-invocation middleware runs around every tool call:

- With `GuardToolCalls()` in the policy, the call's arguments are checked before the tool runs. A blocked call is never executed; the model receives `ToolResultMiddlewareOptions.BlockedToolCallPlaceholder` (default `[blocked: tool call violated guardrail policy]`) as its result.
- With `GuardToolResults()` in the policy, each result is checked before the model sees it, as the text the tool returned (JSON for structured values): the policy's output-phase PII and secrets rules redact it (`IncludeRuleOrders`, by default orders 20, 22 and 25), then the tool-result rule inspects what they produced. A blocked result is replaced with `BlockedPlaceholder`; a sanitized one is substituted.
- The tool calls and results in the final response are still checked afterwards, as a safety net for tools that bypass `FunctionInvokingChatClient` (hosted tools, MCP).

Tune the middleware with `ToolResultMiddlewareOptions` through `UseAgentGuard(policy, toolResultOptions)`.

**With the `IChatClient` decorator**, tool rules see the `FunctionCallContent` and `FunctionResultContent` of each response, streamed or not. Place the decorator inside the `FunctionInvokingChatClient` to vet each model turn before its tool calls run:

```csharp
var client = new ChatClientBuilder(innerClient)
    .UseFunctionInvocation()
    .Use(inner => inner.UseAgentGuard(g => g.BlockPromptInjection().GuardToolCalls()))
    .Build();
```

In that position the decorator runs on every model turn of the tool loop, input rules included. Wrapped around the `FunctionInvokingChatClient` instead, it sees the tool calls only after they have run, so it can reject the response but not stop the calls.

### RAG / Retrieval Guardrails

Filter retrieved knowledge base chunks before they reach the LLM context:

```csharp
// With MAF - use RetrievalGuardrailContextProvider as a context provider
var agent = chatClient
    .AsAIAgent(instructions: "You answer questions using the provided context.")
    .AsBuilder()
    .UseAIContextProviders(new RetrievalGuardrailContextProvider(new()
    {
        RetrievalFunc = async (query, ct) => await vectorStore.SearchAsync(query, ct),
        GuardrailOptions = new() { DetectPromptInjection = true, DetectSecrets = true }
    }))
    .UseAgentGuard(g => g.BlockPromptInjection().RedactPii())
    .Build();

// Or standalone - evaluate chunks directly
var rule = new RetrievalGuardrailRule();
var result = rule.EvaluateChunks(retrievedChunks);
// result.ApprovedChunks - safe to inject into LLM context
// result.FilteredCount - how many chunks were removed
```

### Custom Rules

```csharp
using AgentGuard.Core.Abstractions;

public class NoProfanityRule : IGuardrailRule
{
    public string Name => "no-profanity";
    public GuardrailPhase Phase => GuardrailPhase.Output;

    public ValueTask<GuardrailResult> EvaluateAsync(
        GuardrailContext context,
        CancellationToken cancellationToken = default)
    {
        var hasProfanity = ProfanityDetector.Check(context.Text);

        return ValueTask.FromResult(hasProfanity
            ? GuardrailResult.Blocked("Response contained inappropriate language.")
            : GuardrailResult.Passed());
    }
}

// Register it in a pipeline
var policy = new GuardrailPolicyBuilder()
    .AddRule(new NoProfanityRule())
    .Build();
```

## Rule Execution Order

Rules execute in order of their `Order` property (lower = first). Built-in rules are ordered to maximize efficiency - cheap regex checks run before expensive LLM calls:

| Order | Rule | Type | Phase |
|-------|------|------|-------|
| 5 | `InputNormalizationRule` | Local | Input |
| 8 | `RetrievalGuardrailRule` | Regex | Input |
| 10 | `PromptInjectionRule` | Regex | Input |
| 11 | `DefenderPromptInjectionRule` | ONNX ML (bundled) | Input |
| 12 | `OnnxPromptInjectionRule` | ONNX ML (DeBERTa, optional) | Input |
| 12 | `PIGuardPromptInjectionRule` | ONNX ML (PIGuard, optional) | Input |
| 13 | `RemotePromptInjectionRule` | Remote ML | Input |
| 14 | `AzurePromptShieldRule` | Azure API | Input |
| 15 | `LlmPromptInjectionRule` | LLM | Input |
| 20 | `PiiRule` | Regex + checksum (offline) | Both |
| 20 | `GlinerNerRecognizer` (via `RedactPiiWithNer()`) | ONNX ML (GLiNER, multilingual, optional) | Both |
| 20 | `RemotePiiRecognizer` / `AzurePiiRecognizer` (via `RedactPiiWithRemote()` / `RedactPiiWithAzure()`) | Out-of-process detector / Azure AI Language | Both |
| 22 | `SecretsDetectionRule` | Regex | Both |
| 25 | `LlmPiiDetectionRule` | LLM | Both |
| 35 | `LlmTopicGuardrailRule` | LLM | Input |
| 40 | `TokenLimitRule` | Local | Input/Output |
| 45 | `ToolCallGuardrailRule` | Regex | Output |
| 47 | `ToolResultGuardrailRule` | Regex | Output |
| 50 | `ContentSafetyRule` | Pluggable | Both |
| 50 | `OpirSafetyRule` | ONNX ML (mDeBERTa, multilingual, optional) | Input |
| 55 | `LlmOutputPolicyRule` | LLM | Output |
| 65 | `LlmGroundednessRule` | LLM | Output |
| 75 | `LlmCopyrightRule` | LLM | Output |
| 76 | `AzureProtectedMaterialRule` | Azure API | Output |
| 100 | Custom rules | User-defined | Any |

## Samples

- [Basic Guardrails](samples/BasicGuardrails/) - standalone rule evaluation, no framework dependency
- [IChatClient Guardrails](samples/ChatClientGuardrails/) - `UseAgentGuard()` IChatClient decorator with history propagation, topic boundary, output guardrails, and streaming
- [Agent Framework Integration](samples/AgentFrameworkIntegration/) - `UseAgentGuard()` on a MAF agent with RunAsync and streaming
- [ONNX Guardrails](samples/OnnxGuardrails/) - offline ML-based prompt injection detection with bundled StackOne Defender model + optional DeBERTa v3
- [Opir Multilingual Guardrails](samples/OpirMultilingualGuardrails/) - offline multilingual content-safety detection (toxicity across German, Spanish, Russian, Arabic, Chinese, Hindi) with `BlockUnsafeContentWithOpir()`
- [PII in Agent Framework](samples/AgentFrameworkPii/) - PII handling around a MAF agent: standard input/output redaction, reversible redaction (`.UsePiiReversibleRedaction()` - encrypt before the model, decrypt in the response), and tool-result redaction. Redaction parts run offline against a scripted agent; the tool-calling part is gated on `OPENAI_BASE_URL`/`OPENAI_MODEL`
- [Custom Rules](samples/CustomRules/) - implementing and composing custom guardrail rules
- [Azure Integration](samples/AzureIntegration/) - using Azure AI Content Safety for production
- [Workflow Guardrails](samples/WorkflowGuardrails/) - wrapping MAF workflow executors with `.WithGuardrails()` decorator
- [Output Guardrails](samples/OutputGuardrails/) - LLM output validation (policy, groundedness, copyright)
- [Tool Call Guardrails](samples/ToolCallGuardrails/) - blocking SQL injection, path traversal, SSRF in agent tool calls
- [Tool Result Guardrails](samples/ToolResultGuardrails/) - detecting indirect prompt injection in tool results (poisoned emails, documents); standalone rule + MAF function-invocation interception
- [Dynamic Guardrails](samples/DynamicGuardrails/) - per-request rule enabling with `.When()` / `.Unless()` (e.g. disabling the English-centric Defender classifier for non-English users)
- [Decision Ledger](samples/DecisionLedger/) - tamper-evident, hash-chained audit trail of pipeline decisions: recording, chain verification, tamper detection, and JSON export
- [Remote PII](samples/RemotePii/) - out-of-process PII detection: a generic HTTP detector via `.RedactPiiWithRemote()` (an in-process stub that wraps GLiNER when the `AGENTGUARD_GLINER_*` variables are set) and Azure AI Language's native PERSON/ADDRESS via `.RedactPiiWithAzure()` (gated on `AZURE_LANGUAGE_ENDPOINT`/`AZURE_LANGUAGE_KEY`)

## Documentation

- [Getting Started](docs/getting-started.md)
- [Rule Reference](docs/rules-reference.md)
- [Custom Rules Guide](docs/custom-rules.md)
- [Configuration](docs/configuration.md)
- [Observability (OpenTelemetry)](docs/observability.md)
- [Azure Integration](docs/azure-integration.md)
- [Remote PII Detection](docs/remote-pii.md)

## Requirements

- .NET 10.0 or later
- Microsoft Agent Framework 1.22.0 or later *(only if using `AgentGuard.AgentFramework`)*

### Optional ONNX models

The bundled StackOne Defender prompt-injection model ships in the Kyoto NuGet package that `AgentGuard.Onnx` depends on, so it needs no download. The other ONNX models (GLiNER PII NER, Opir multilingual content safety, PIGuard, and the generic DeBERTa injection classifier) are opt-in, BYO-download prebuilt exports hosted on Hugging Face. To pull them for the samples and the gated E2E tests, run the bootstrap script from a sibling checkout of the [Kyoto](https://github.com/filipw/kyoto) repo (see [`eng/MODELS.md`](eng/MODELS.md)):

```bash
cd ../kyoto
./bootstrap-models.sh              # all models (~1.9 GB) into ./models (gitignored)
./bootstrap-models.sh gliner       # or just the PII NER model
source ./models/env.sh             # export the AGENTGUARD_*_PATH variables
cd ../AgentGuard
dotnet test AgentGuard.slnx        # the gated ONNX/PII E2E tests run instead of skipping
```

### LLM end-to-end tests

The LLM E2E tests run against any OpenAI-compatible endpoint and are skipped unless `OPENAI_BASE_URL` and `OPENAI_MODEL` are set. `OPENAI_API_KEY`, `OPENAI_MAX_TOKENS` (default 1000) and `OPENAI_TEMPERATURE` are optional; leave `OPENAI_TEMPERATURE` unset to use the model's default, since newer reasoning models reject an explicit value.


## Acknowledgements

- Prompt injection detection patterns and LLM prompt templates are informed by the [Arcanum Prompt Injection Taxonomy](https://github.com/Arcanum-Sec/arc_pi_taxonomy) by Jason Haddix / Arcanum Information Security (CC BY 4.0)

## License

This project is licensed under the MIT License - see [LICENSE](LICENSE) for details.
