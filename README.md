# AgentGuard

**Declarative guardrails and safety controls for .NET AI agents**

[![NuGet](https://img.shields.io/nuget/v/AgentGuard.Core.svg)](https://www.nuget.org/packages/AgentGuard.Core)
[![Build](https://github.com/filipw/AgentGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/filipw/AgentGuard/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

What [NeMo Guardrails](https://github.com/NVIDIA/NeMo-Guardrails) and [Guardrails AI](https://github.com/guardrails-ai/guardrails) do for Python, **AgentGuard** does for .NET — with the fluent APIs, composable rules, and type safety that .NET developers expect.

---

## Why AgentGuard?

Every AI agent needs the same safety guardrails: PII detection, prompt injection blocking, topic enforcement, token limits, output validation. AgentGuard provides all of this as composable, testable, declarative rules.

The core engine is **framework-agnostic** — use it standalone, with Microsoft Agent Framework, Semantic Kernel, or any other .NET AI stack. Framework-specific adapters (like `AgentGuard.AgentFramework` for MAF) wire guardrails into the host's middleware pipeline.

```csharp
// Use the guardrail engine standalone — no framework dependency needed
var policy = new GuardrailPolicyBuilder()
    .NormalizeInput()              // decode base64/hex/unicode evasion tricks
    .BlockPromptInjection()        // regex-based injection detection
    .RedactPII(PiiCategory.Email | PiiCategory.Phone | PiiCategory.SSN)
    .EnforceTopicBoundary("customer-support", "billing", "returns")
    .LimitInputTokens(4000)
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

- **Input normalization** — decodes evasion encodings (base64, hex, reversed text, Unicode homoglyphs) before downstream rules evaluate the text, catching attacks hidden via encoding tricks
- **Prompt injection detection** — blocks jailbreak attempts, system prompt extraction, role-play attacks, end sequence injection, variable expansion, framing attacks, and rule addition with configurable sensitivity levels (Low/Medium/High). Patterns based on the [Arcanum Prompt Injection Taxonomy](https://github.com/Arcanum-Sec/arc_pi_taxonomy)
- **PII redaction** — detects and redacts emails, phone numbers, SSNs, credit cards, IP addresses, dates of birth, and custom patterns on input and output
- **Topic boundary enforcement** — keyword-based topic matching with pluggable `ITopicSimilarityProvider` for embedding-based similarity. `EmbeddingSimilarityProvider` in `AgentGuard.Local` uses any `IEmbeddingGenerator<string, Embedding<float>>` for cosine similarity with automatic topic embedding caching
- **Token limits** — enforces input/output token budgets using `Microsoft.ML.Tokenizers` (cl100k_base) with configurable overflow strategies (Reject/Truncate/Warn)
- **Content safety** — severity-based filtering via pluggable `IContentSafetyClassifier` (Azure AI Content Safety adapter included)

### ONNX ML-based rules (fast, accurate, offline)

- **ONNX prompt injection detection** — uses a fine-tuned DeBERTa v3 model (`protectai/deberta-v3-base-prompt-injection-v2`) for ML-based classification. Runs fully offline with ~10ms inference time. Sits between regex (order 10) and LLM (order 15) at order 12. Returns confidence scores in metadata. Install via `AgentGuard.Onnx` package. Download the model with `./eng/download-onnx-model.sh`.

### LLM-based rules (accurate, pluggable via `IChatClient`)

For teams that need higher accuracy than regex, AgentGuard provides LLM-as-judge guardrail rules that work with any `IChatClient` (Azure OpenAI, Ollama, local models, etc.):

- **LLM prompt injection detection** — catches sophisticated attacks that regex misses: narrative smuggling, meta-prompting, cognitive overload, multi-chain attacks, and more. Prompt templates cover all 12 attack technique families and 20 evasion methods from the [Arcanum PI Taxonomy](https://github.com/Arcanum-Sec/arc_pi_taxonomy). Returns structured threat classification metadata (technique, intent, evasion, confidence) for operational telemetry
- **LLM PII detection & redaction** — catches unstructured PII like full names, physical addresses, and contextual identifiers that regex can't find. Supports block or redact modes
- **LLM topic boundary enforcement** — semantic topic classification that understands intent, not just keywords
- **LLM output policy enforcement** — checks if agent responses violate custom policy constraints (e.g. "never recommend competitors", "always include a disclaimer"). Configurable policy description with block or warn modes
- **LLM groundedness checking** — detects hallucinated facts and claims not supported by the conversation context. Uses conversation history for grounding evaluation
- **LLM copyright detection** — catches verbatim reproduction of copyrighted material (song lyrics, book passages, articles, restrictively-licensed code). Kill switch for copyright violations

```csharp
using AgentGuard.Onnx;

// Three-tier prompt injection detection: Regex → ONNX ML → LLM
var policy = new GuardrailPolicyBuilder()
    .BlockPromptInjection()                              // tier 1: fast regex (order 10)
    .BlockPromptInjectionWithOnnx(                       // tier 2: ML classifier (order 12)
        "./models/model.onnx", "./models/spm.model")
    .BlockPromptInjectionWithLlm(chatClient)             // tier 3: LLM judge (order 15)
    .DetectPIIWithLlm(chatClient, new() { Action = PiiAction.Redact })
    .EnforceTopicBoundaryWithLlm(chatClient, "billing", "payments")
    .LimitInputTokens(4000)
    .Build();
```

All LLM rules ship with built-in prompt templates and support custom system prompt overrides. They fail open on LLM errors — your agent keeps working even if the classifier is down.

### Streaming support

AgentGuard works with both `RunAsync` and `RunStreamingAsync` when used with MAF. Two streaming modes are available:

- **Buffer-then-release** (default) — buffers all output chunks, evaluates guardrails on the complete text, then yields original chunks if passed.
- **Progressive with retraction** — tokens stream through to the user immediately while guardrails evaluate progressively. On violation, retraction/replacement events are emitted so the UI can hide/replace content already shown. Follows the Azure OpenAI content filter pattern.

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

- **Output validation** — fluent predicate-based assertions on agent responses
- **Custom rules** — implement `IGuardrailRule` to add your own checks with full access to the conversation context
- **Framework-agnostic core** — use the rules engine standalone or plug into MAF, Semantic Kernel, or any framework
- **Fully testable** — every rule is a pure function; mock the pipeline, assert the behavior
- **Configuration-driven** — define policies entirely in `appsettings.json` with full support for all rule types, named policies, and DI resolution for LLM/cloud rules
- **Offline-first** — works without any cloud services; optionally upgrade to Azure AI Content Safety or LLM-based rules for production accuracy

## Packages

| Package | Description | NuGet |
|---------|-------------|-------|
| `AgentGuard.Core` | Framework-agnostic core: abstractions, rules engine, fluent builder, all 14 built-in rules | [![NuGet](https://img.shields.io/nuget/v/AgentGuard.Core.svg)](https://www.nuget.org/packages/AgentGuard.Core) |
| `AgentGuard.AgentFramework` | Microsoft Agent Framework adapter: `UseAgentGuard()` middleware for `AIAgentBuilder` | [![NuGet](https://img.shields.io/nuget/v/AgentGuard.AgentFramework.svg)](https://www.nuget.org/packages/AgentGuard.AgentFramework) |
| `AgentGuard.Workflows` | Workflow guardrails — decorates MAF `Executor` with guardrails at step boundaries | [![NuGet](https://img.shields.io/nuget/v/AgentGuard.Workflows.svg)](https://www.nuget.org/packages/AgentGuard.Workflows) |
| `AgentGuard.Onnx` | ONNX-based ML classifiers — offline prompt injection detection with DeBERTa v3 | [![NuGet](https://img.shields.io/nuget/v/AgentGuard.Onnx.svg)](https://www.nuget.org/packages/AgentGuard.Onnx) |
| `AgentGuard.Local` | Offline classifiers (keyword similarity, embedding-based topic similarity) | [![NuGet](https://img.shields.io/nuget/v/AgentGuard.Local.svg)](https://www.nuget.org/packages/AgentGuard.Local) |
| `AgentGuard.Azure` | Azure AI Content Safety integration | [![NuGet](https://img.shields.io/nuget/v/AgentGuard.Azure.svg)](https://www.nuget.org/packages/AgentGuard.Azure) |
| `AgentGuard.Hosting` | DI registration, named policy factory, `appsettings.json` config binding | [![NuGet](https://img.shields.io/nuget/v/AgentGuard.Hosting.svg)](https://www.nuget.org/packages/AgentGuard.Hosting) |

## Quick Start

### Install

```bash
dotnet add package AgentGuard.Core --prerelease
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

// Use it exactly like a normal agent — guardrails are transparent
var response = await guardedAgent.RunAsync(messages, session, options);
```

### With LLM-based rules

```csharp
using Microsoft.Extensions.AI;
using AgentGuard.Core.Builders;
using AgentGuard.Core.Rules.LLM;

// Use any IChatClient — Azure OpenAI, Ollama, etc.
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

// Use any IEmbeddingGenerator — OpenAI, Ollama, local ONNX, etc.
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

Define guardrail policies entirely in configuration — no code changes needed to adjust rules:

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

MAF workflows compose multiple `Executor` steps into a DAG. `AgentGuard.Workflows` lets you wrap individual executors with guardrails at step boundaries using the `.WithGuardrails()` decorator:

```bash
dotnet add package AgentGuard.Workflows --prerelease
```

```csharp
using AgentGuard.Workflows;

// Wrap a void executor with input guardrails
var guardedInput = myInputExecutor.WithGuardrails(b => b
    .NormalizeInput()
    .BlockPromptInjection(Sensitivity.High)
    .RedactPII());

// Wrap a typed executor with input + output guardrails
var guardedProcessor = myProcessorExecutor.WithGuardrails(b => b
    .RedactPII()
    .ValidateOutput(text => !text.Contains("internal-only"), "Leaked internal info"));

// Use in your workflow — GuardedExecutor is still an Executor
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

Rules execute in order of their `Order` property (lower = first). Built-in rules are ordered to maximize efficiency — cheap regex checks run before expensive LLM calls:

| Order | Rule | Type | Phase |
|-------|------|------|-------|
| 5 | `InputNormalizationRule` | Local | Input |
| 10 | `PromptInjectionRule` | Regex | Input |
| 12 | `OnnxPromptInjectionRule` | ONNX ML | Input |
| 15 | `LlmPromptInjectionRule` | LLM | Input |
| 20 | `PiiRedactionRule` | Regex | Both |
| 25 | `LlmPiiDetectionRule` | LLM | Both |
| 30 | `TopicBoundaryRule` | Keywords | Input |
| 35 | `LlmTopicGuardrailRule` | LLM | Input |
| 40 | `TokenLimitRule` | Local | Input/Output |
| 50 | `ContentSafetyRule` | Pluggable | Both |
| 55 | `LlmOutputPolicyRule` | LLM | Output |
| 60 | `OutputTopicBoundaryRule` | Embedding | Output |
| 65 | `LlmGroundednessRule` | LLM | Output |
| 75 | `LlmCopyrightRule` | LLM | Output |
| 100 | Custom rules | User-defined | Any |

## Samples

- [Basic Guardrails](samples/BasicGuardrails/) — standalone rule evaluation, no framework dependency
- [Agent Framework Integration](samples/AgentFrameworkIntegration/) — `UseAgentGuard()` on a MAF agent with RunAsync and streaming
- [ONNX Guardrails](samples/OnnxGuardrails/) — offline ML-based prompt injection detection with DeBERTa v3
- [Custom Rules](samples/CustomRules/) — implementing and composing custom guardrail rules
- [Azure Integration](samples/AzureIntegration/) — using Azure AI Content Safety for production
- [Workflow Guardrails](samples/WorkflowGuardrails/) — wrapping MAF workflow executors with `.WithGuardrails()` decorator
- [Output Guardrails](samples/OutputGuardrails/) — LLM output validation (policy, groundedness, copyright)

## Documentation

- [Getting Started](docs/getting-started.md)
- [Rule Reference](docs/rules-reference.md)
- [Custom Rules Guide](docs/custom-rules.md)
- [Configuration](docs/configuration.md)
- [Azure Integration](docs/azure-integration.md)

## Requirements

- .NET 10.0 or later
- Microsoft Agent Framework 1.0.0-rc4 or later *(only if using `AgentGuard.AgentFramework` or `AgentGuard.Workflows`)*


## Acknowledgements

- Prompt injection detection patterns and LLM prompt templates are informed by the [Arcanum Prompt Injection Taxonomy](https://github.com/Arcanum-Sec/arc_pi_taxonomy) by Jason Haddix / Arcanum Information Security (CC BY 4.0)

## License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.
