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
// Use the guardrail engine standalone - no framework dependency needed
var policy = new GuardrailPolicyBuilder()
    .NormalizeInput()              // decode base64/hex/unicode evasion tricks
    .GuardRetrieval()              // filter poisoned RAG chunks
    .BlockPromptInjection()        // regex-based injection detection
    .RedactPII(PiiCategory.Email | PiiCategory.Phone | PiiCategory.SSN)
    .DetectSecrets()               // block API keys, tokens, connection strings
    .EnforceTopicBoundary("customer-support", "billing", "returns")
    .LimitInputTokens(4000)
    .GuardToolCalls()              // inspect tool call arguments for injection
    .GuardToolResults()            // detect indirect injection in tool results
    .Build();

var pipeline = new GuardrailPipeline(policy, logger);
var result = await pipeline.RunAsync(new GuardrailContext { Text = userInput, Phase = GuardrailPhase.Input });

if (result.IsBlocked)
    Console.WriteLine($"Blocked: {result.BlockingResult!.Reason}");
```

```csharp
// Or plug into Microsoft Agent Framework with two lines
using AgentGuard.AgentFramework;

var guardedAgent = agent
    .AsBuilder()
    .UseAgentGuard(g => g
        .BlockPromptInjection()
        .RedactPII()
        .EnforceTopicBoundary("customer-support")
        .OnViolation(v => v.RejectWithMessage("I can only help with customer support topics."))
    )
    .Build();
```

## Features

### Regex-based rules (fast, zero-cost, offline)

- **Input normalization** - decodes evasion encodings (base64, hex, reversed text, Unicode homoglyphs) before downstream rules evaluate the text, catching attacks hidden via encoding tricks
- **Prompt injection detection** - blocks jailbreak attempts, system prompt extraction, role-play attacks, end sequence injection, variable expansion, framing attacks, and rule addition with configurable sensitivity levels (Low/Medium/High). Patterns based on the [Arcanum Prompt Injection Taxonomy](https://github.com/Arcanum-Sec/arc_pi_taxonomy)
- **PII redaction** - detects and redacts emails, phone numbers, SSNs, credit cards, IP addresses, dates of birth, and custom patterns on input and output
- **Topic boundary enforcement** - keyword-based topic matching with pluggable `ITopicSimilarityProvider` for embedding-based similarity. `EmbeddingSimilarityProvider` in `AgentGuard.Local` uses any `IEmbeddingGenerator<string, Embedding<float>>` for cosine similarity with automatic topic embedding caching
- **Token limits** - enforces input/output token budgets using `Microsoft.ML.Tokenizers` (cl100k_base) with configurable overflow strategies (Reject/Truncate/Warn)
- **Secrets detection** - detects API keys (AWS, GitHub, Azure, Slack), JWT tokens, private keys, connection strings, bearer tokens. Block or redact actions with custom patterns and optional Shannon entropy-based detection
- **Content safety** - severity-based filtering via pluggable `IContentSafetyClassifier` (Azure AI Content Safety adapter included). Detects harmful content (hate, violence, self-harm, sexual) - a complementary layer to prompt injection detection, not a substitute for it
- **Azure Prompt Shields** - dedicated prompt injection detection via Azure AI Content Safety's Prompt Shield API (`text:shieldPrompt`). Detects user prompt attacks (jailbreaks, role-play, encoding attacks) and document attacks (indirect injection in grounded content). **F1 50.3%** (85.9% precision, 35.6% recall) on adversarial benchmarks — complements local Defender (F1 ~97%) with a cloud-based signal. Order 14. Install via `AgentGuard.Azure` package
- **Azure Protected Material detection** - detects copyrighted text (lyrics, articles, recipes) and code from GitHub repositories in LLM-generated output via `text:detectProtectedMaterial` and `text:detectProtectedMaterialForCode`. Code detection returns license info and source URLs. No C# SDK exists for these APIs — AgentGuard provides the only .NET client. Output phase (order 76), supports Block/Warn actions. Install via `AgentGuard.Azure` package

### RAG & Agentic guardrails (zero-cost, offline)

- **Retrieval guardrails** - filters retrieved chunks before they reach the LLM context. Detects prompt injection, secrets, and PII in knowledge base content. Supports relevance score filtering, max chunk limits, remove/sanitize actions, and custom filters. Integrates with MAF via `RetrievalGuardrailContextProvider`
- **Tool call guardrails** - inspects agent tool call arguments for SQL injection, code injection, path traversal, command injection, SSRF, template injection, and XSS. Per-tool and per-argument allowlists for tools that legitimately accept code/SQL. Automatically extracted from MAF agent responses
- **Tool result guardrails** - detects indirect prompt injection hidden in tool call results (emails, documents, API responses). Three-tier risk-based detection with tool-specific risk profiles (email=high, docs=medium, calculator=low). Supports block or sanitize actions, Unicode control character stripping, and custom patterns. Inspired by [StackOneHQ/defender](https://github.com/StackOneHQ/defender)

### ONNX ML-based rules (fast, accurate, offline)

- **StackOne Defender prompt injection detection** - uses the [StackOne Defender](https://github.com/StackOneHQ/defender) fine-tuned MiniLM-L6-v2 ONNX model (~22 MB, bundled in NuGet) for ML-based classification. **F1 ~0.97** on adversarial benchmarks, ~8 ms inference, fully offline. **No download required** - the model is bundled with `AgentGuard.Onnx`. Order 11 (default). Also supports optional DeBERTa v3 model (order 12, separate download via `./eng/download-onnx-model.sh`)

### Remote ML classifier (SOTA models via HTTP)

- **Remote prompt injection detection** - calls external model servers (Ollama, vLLM, HuggingFace TGI, custom FastAPI endpoints) for ML-based classification. Designed for SOTA models like [Sentinel-v2](https://huggingface.co/rogue-security/prompt-injection-jailbreak-sentinel-v2) (Qwen3-0.6B, F1 ~0.957, 32K context). Lightweight - no native ML dependencies, just `HttpClient`. Pluggable `IRemoteClassifier` abstraction. Order 13, fails open by default. Install via `AgentGuard.RemoteClassifier` package.

### Remote ML classifier (SOTA models via HTTP)

- **Remote prompt injection detection** — calls external model servers (Ollama, vLLM, HuggingFace TGI, custom FastAPI endpoints) for ML-based classification. Designed for SOTA models like [Sentinel-v2](https://huggingface.co/rogue-security/prompt-injection-jailbreak-sentinel-v2) (Qwen3-0.6B, F1 ~0.957, 32K context). Lightweight — no native ML dependencies, just `HttpClient`. Pluggable `IRemoteClassifier` abstraction. Order 13, fails open by default. Install via `AgentGuard.RemoteClassifier` package.

### LLM-based rules (accurate, pluggable via `IChatClient`)

For teams that need higher accuracy than regex, AgentGuard provides LLM-as-judge guardrail rules that work with any `IChatClient` (Azure OpenAI, Ollama, local models, etc.):

- **LLM prompt injection detection** - catches sophisticated attacks that regex misses: narrative smuggling, meta-prompting, cognitive overload, multi-chain attacks, and more. Prompt templates cover all 12 attack technique families and 20 evasion methods from the [Arcanum PI Taxonomy](https://github.com/Arcanum-Sec/arc_pi_taxonomy). Returns structured threat classification metadata (technique, intent, evasion, confidence) for operational telemetry
- **LLM PII detection & redaction** - catches unstructured PII like full names, physical addresses, and contextual identifiers that regex can't find. Supports block or redact modes
- **LLM topic boundary enforcement** - semantic topic classification that understands intent, not just keywords
- **LLM output policy enforcement** - checks if agent responses violate custom policy constraints (e.g. "never recommend competitors", "always include a disclaimer"). Configurable policy description with block or warn modes
- **LLM groundedness checking** - detects hallucinated facts and claims not supported by the conversation context. Uses conversation history for grounding evaluation
- **LLM copyright detection** - catches verbatim reproduction of copyrighted material (song lyrics, book passages, articles, restrictively-licensed code). Kill switch for copyright violations

```csharp
using AgentGuard.Onnx;
using AgentGuard.Azure.PromptShield;

// Six-tier prompt injection detection: Regex → Defender → DeBERTa → Remote ML → Prompt Shield → LLM
var policy = new GuardrailPolicyBuilder()
    .BlockPromptInjection()                              // tier 1: fast regex (order 10)
    .BlockPromptInjectionWithOnnx()                      // tier 2: Defender ML (order 11, bundled)
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

AgentGuard works with both `RunAsync` and `RunStreamingAsync` when used with MAF. Two streaming modes are available:

- **Buffer-then-release** (default) - buffers all output chunks, evaluates guardrails on the complete text, then yields original chunks if passed.
- **Progressive with retraction** - tokens stream through to the user immediately while guardrails evaluate progressively. On violation, retraction/replacement events are emitted so the UI can hide/replace content already shown. Follows the Azure OpenAI content filter pattern.

```csharp
// Enable progressive streaming
var policy = new GuardrailPolicyBuilder()
    .RedactPII()
    .CheckGroundedness(chatClient)
    .UseProgressiveStreaming()  // tokens flow immediately, retract on violation
    .Build();
```

Fast rules (regex, local) evaluate on every check cycle. Expensive LLM rules only evaluate at the end. Rules can declare their preference via `IStreamingGuardrailRule`.

### Additional features

- **Output validation** - fluent predicate-based assertions on agent responses
- **Custom rules** - implement `IGuardrailRule` to add your own checks with full access to the conversation context
- **Framework-agnostic core** - use the rules engine standalone or plug into MAF, Semantic Kernel, or any framework
- **Fully testable** - every rule is a pure function; mock the pipeline, assert the behavior
- **Configuration-driven** - define policies entirely in `appsettings.json` with full support for all rule types, named policies, and DI resolution for LLM/cloud rules
- **Offline-first** - works without any cloud services; optionally upgrade to Azure AI Content Safety or LLM-based rules for production accuracy

## Packages

| Package | Description | NuGet |
|---------|-------------|-------|
| `AgentGuard` | **All-in-one package**: core rules engine, bundled Defender ONNX model (F1 ~0.97), offline classifiers | [![NuGet](https://img.shields.io/nuget/v/AgentGuard.svg)](https://www.nuget.org/packages/AgentGuard) |
| `AgentGuard.Core` | Framework-agnostic core only: abstractions, rules engine, fluent builder, all 19 built-in rules | [![NuGet](https://img.shields.io/nuget/v/AgentGuard.Core.svg)](https://www.nuget.org/packages/AgentGuard.Core) |
| `AgentGuard.AgentFramework` | Microsoft Agent Framework adapter: `UseAgentGuard()` middleware + workflow guardrails via `.WithGuardrails()` | [![NuGet](https://img.shields.io/nuget/v/AgentGuard.AgentFramework.svg)](https://www.nuget.org/packages/AgentGuard.AgentFramework) |
| `AgentGuard.Onnx` | ONNX-based ML classifiers - bundled StackOne Defender model (F1 ~0.97) + optional DeBERTa v3 | [![NuGet](https://img.shields.io/nuget/v/AgentGuard.Onnx.svg)](https://www.nuget.org/packages/AgentGuard.Onnx) |
| `AgentGuard.RemoteClassifier` | Remote ML classifier via HTTP - call Sentinel-v2, Ollama, vLLM, or custom endpoints | [![NuGet](https://img.shields.io/nuget/v/AgentGuard.RemoteClassifier.svg)](https://www.nuget.org/packages/AgentGuard.RemoteClassifier) |
| `AgentGuard.Local` | Offline classifiers (keyword similarity, embedding-based topic similarity) | [![NuGet](https://img.shields.io/nuget/v/AgentGuard.Local.svg)](https://www.nuget.org/packages/AgentGuard.Local) |
| `AgentGuard.Azure` | Azure AI Content Safety: Prompt Shields (injection detection, F1 ~0.503) + protected material detection (text & code with license citations) + text analysis (harmful content) + blocklists | [![NuGet](https://img.shields.io/nuget/v/AgentGuard.Azure.svg)](https://www.nuget.org/packages/AgentGuard.Azure) |
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
using Microsoft.Extensions.Logging.Abstractions;

var policy = new GuardrailPolicyBuilder()
    .BlockPromptInjection()
    .RedactPII()
    .EnforceTopicBoundary("customer-support")
    .OnViolation(v => v.RejectWithMessage("I can only help with customer support topics."))
    .Build();

var pipeline = new GuardrailPipeline(policy, NullLogger<GuardrailPipeline>.Instance);

var ctx = new GuardrailContext { Text = userInput, Phase = GuardrailPhase.Input };
var result = await pipeline.RunAsync(ctx);

if (result.IsBlocked)
    Console.WriteLine($"Blocked: {result.BlockingResult!.Reason}");
else if (result.WasModified)
    Console.WriteLine($"Modified: {result.FinalText}");
```

### With Microsoft Agent Framework

```bash
dotnet add package AgentGuard.AgentFramework --prerelease
```

```csharp
using AgentGuard.AgentFramework;

var guardedAgent = agent
    .AsBuilder()
    .UseAgentGuard(g => g
        .BlockPromptInjection()
        .RedactPII()
        .EnforceTopicBoundary("customer-support")
        .OnViolation(v => v.RejectWithMessage("I can only help with customer support topics."))
    )
    .Build();

// Use it exactly like a normal agent - guardrails are transparent
var response = await guardedAgent.RunAsync(messages, session, options);
```

### With LLM-based rules

```csharp
using Microsoft.Extensions.AI;
using AgentGuard.Core.Builders;
using AgentGuard.Core.Rules.LLM;

// Use any IChatClient - Azure OpenAI, Ollama, etc.
IChatClient classifier = new OllamaChatClient("llama3");

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
builder.Services.AddAgentGuard(options =>
{
    options.DefaultPolicy(policy => policy
        .BlockPromptInjection()
        .RedactPII()
        .LimitOutputTokens(2000));

    options.AddPolicy("strict", policy => policy
        .BlockPromptInjection(sensitivity: Sensitivity.High)
        .RedactPII(PiiCategory.All)
        .EnforceTopicBoundary("billing"));
});
```

### With Embedding-based Topic Boundary

```csharp
using Microsoft.Extensions.AI;
using AgentGuard.Local.Classifiers;
using AgentGuard.Core.Builders;

// Use any IEmbeddingGenerator - OpenAI, Ollama, local ONNX, etc.
IEmbeddingGenerator<string, Embedding<float>> embeddings = /* your provider */;

var policy = new GuardrailPolicyBuilder()
    .BlockPromptInjection()
    .EnforceTopicBoundary(
        new EmbeddingSimilarityProvider(embeddings),
        similarityThreshold: 0.4f,
        "billing", "returns", "customer support")
    .LimitInputTokens(4000)
    .Build();
```

### With `appsettings.json` Configuration

Define guardrail policies entirely in configuration - no code changes needed to adjust rules:

```json
{
  "AgentGuard": {
    "DefaultPolicy": {
      "Rules": [
        { "Type": "PromptInjection", "Sensitivity": "High" },
        { "Type": "PiiRedaction", "Categories": "Email,Phone,SSN" },
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

See [Configuration docs](docs/configuration.md) for the full JSON schema covering all rule types.

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
    .RedactPII());

// Wrap a typed executor with input + output guardrails
var guardedProcessor = myProcessorExecutor.WithGuardrails(b => b
    .RedactPII()
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

The `ITextExtractor` interface bridges typed workflow messages to string-based guardrail rules. The built-in `DefaultTextExtractor` handles `string`, `ChatMessage`, `AgentResponse`, and objects with a `Text` property.

### Tool Call Guardrails

When agents use tools, the LLM generates tool call arguments that are passed to external systems (databases, APIs, file systems). AgentGuard inspects these arguments for injection attacks:

```csharp
// With MAF - tool calls are automatically extracted from agent responses
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
    .UseAgentGuard(g => g.BlockPromptInjection().RedactPII())
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
| 12 | `OnnxPromptInjectionRule` | ONNX ML (DeBERTa) | Input |
| 13 | `RemotePromptInjectionRule` | Remote ML | Input |
| 14 | `AzurePromptShieldRule` | Azure API | Input |
| 15 | `LlmPromptInjectionRule` | LLM | Input |
| 20 | `PiiRedactionRule` | Regex | Both |
| 22 | `SecretsDetectionRule` | Regex | Both |
| 25 | `LlmPiiDetectionRule` | LLM | Both |
| 30 | `TopicBoundaryRule` | Keywords | Input |
| 35 | `LlmTopicGuardrailRule` | LLM | Input |
| 40 | `TokenLimitRule` | Local | Input/Output |
| 45 | `ToolCallGuardrailRule` | Regex | Output |
| 47 | `ToolResultGuardrailRule` | Regex | Output |
| 50 | `ContentSafetyRule` | Pluggable | Both |
| 55 | `LlmOutputPolicyRule` | LLM | Output |
| 60 | `OutputTopicBoundaryRule` | Embedding | Output |
| 65 | `LlmGroundednessRule` | LLM | Output |
| 75 | `LlmCopyrightRule` | LLM | Output |
| 100 | Custom rules | User-defined | Any |

## Samples

- [Basic Guardrails](samples/BasicGuardrails/) - standalone rule evaluation, no framework dependency
- [Agent Framework Integration](samples/AgentFrameworkIntegration/) - `UseAgentGuard()` on a MAF agent with RunAsync and streaming
- [ONNX Guardrails](samples/OnnxGuardrails/) - offline ML-based prompt injection detection with bundled StackOne Defender model + optional DeBERTa v3
- [Custom Rules](samples/CustomRules/) - implementing and composing custom guardrail rules
- [Azure Integration](samples/AzureIntegration/) - using Azure AI Content Safety for production
- [Workflow Guardrails](samples/WorkflowGuardrails/) - wrapping MAF workflow executors with `.WithGuardrails()` decorator
- [Output Guardrails](samples/OutputGuardrails/) - LLM output validation (policy, groundedness, copyright)
- [Tool Call Guardrails](samples/ToolCallGuardrails/) - blocking SQL injection, path traversal, SSRF in agent tool calls

## Documentation

- [Getting Started](docs/getting-started.md)
- [Rule Reference](docs/rules-reference.md)
- [Custom Rules Guide](docs/custom-rules.md)
- [Configuration](docs/configuration.md)
- [Azure Integration](docs/azure-integration.md)

## Requirements

- .NET 10.0 or later
- Microsoft Agent Framework 1.0.0-rc4 or later *(only if using `AgentGuard.AgentFramework`)*


## Acknowledgements

- Prompt injection detection patterns and LLM prompt templates are informed by the [Arcanum Prompt Injection Taxonomy](https://github.com/Arcanum-Sec/arc_pi_taxonomy) by Jason Haddix / Arcanum Information Security (CC BY 4.0)

## License

This project is licensed under the MIT License - see [LICENSE](LICENSE) for details.
