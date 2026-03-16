# AgentGuard

**Declarative guardrails and safety controls for Microsoft Agent Framework (.NET)**

[![NuGet](https://img.shields.io/nuget/v/AgentGuard.Core.svg)](https://www.nuget.org/packages/AgentGuard.Core)
[![Build](https://github.com/filipw/AgentGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/filipw/AgentGuard/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

What [NeMo Guardrails](https://github.com/NVIDIA/NeMo-Guardrails) and [Guardrails AI](https://github.com/guardrails-ai/guardrails) do for Python, **AgentGuard** does for .NET — with the fluent APIs, middleware integration, and type safety that .NET developers expect.

---

## Why AgentGuard?

Microsoft Agent Framework provides raw middleware hooks for intercepting agent runs, but every team ends up writing the same boilerplate: PII detection, prompt injection blocking, topic enforcement, token limits, output validation. AgentGuard provides all of this as composable, testable, declarative rules that plug directly into MAF's middleware pipeline.

```csharp
// Add guardrails to any MAF agent in two lines
var guardedAgent = agent
    .AsBuilder()
    .UseAgentGuard(g => g
        .BlockPromptInjection()
        .RedactPII(PiiCategory.Email | PiiCategory.Phone | PiiCategory.SSN)
        .EnforceTopicBoundary("customer-support", "billing", "returns")
        .LimitInputTokens(4000)
        .LimitOutputTokens(2000)
        .ValidateOutput(o => !o.Contains("internal use only"))
    )
    .Build();
```

## Features

### Regex-based rules (fast, zero-cost, offline)

- **Prompt injection detection** — blocks jailbreak attempts, system prompt extraction, and role-play attacks with configurable sensitivity levels (Low/Medium/High)
- **PII redaction** — detects and redacts emails, phone numbers, SSNs, credit cards, IP addresses, dates of birth, and custom patterns on input and output
- **Topic boundary enforcement** — keyword-based topic matching with pluggable `ITopicSimilarityProvider` for embedding-based similarity
- **Token limits** — enforces input/output token budgets using `Microsoft.ML.Tokenizers` (cl100k_base) with configurable overflow strategies (Reject/Truncate/Warn)
- **Content safety** — severity-based filtering via pluggable `IContentSafetyClassifier` (Azure AI Content Safety adapter included)

### LLM-based rules (accurate, pluggable via `IChatClient`)

For teams that need higher accuracy than regex, AgentGuard provides LLM-as-judge guardrail rules that work with any `IChatClient` (Azure OpenAI, Ollama, local models, etc.):

- **LLM prompt injection detection** — catches sophisticated attacks that regex misses: encoding tricks, indirect injection, multi-turn attacks, and multilingual payloads
- **LLM PII detection & redaction** — catches unstructured PII like full names, physical addresses, and contextual identifiers that regex can't find. Supports block or redact modes
- **LLM topic boundary enforcement** — semantic topic classification that understands intent, not just keywords

```csharp
var guardedAgent = agent
    .AsBuilder()
    .UseAgentGuard(g => g
        .BlockPromptInjection()                              // fast regex layer
        .BlockPromptInjectionWithLlm(chatClient)             // accurate LLM layer
        .DetectPIIWithLlm(chatClient, new() { Action = PiiAction.Redact })
        .EnforceTopicBoundaryWithLlm(chatClient, "billing", "payments")
        .LimitInputTokens(4000)
    )
    .Build();
```

All LLM rules ship with built-in prompt templates and support custom system prompt overrides. They fail open on LLM errors — your agent keeps working even if the classifier is down.

### Streaming support

GuardGuard works with both `RunAsync` and `RunStreamingAsync`. Streaming middleware buffers output chunks and evaluates them against output guardrails before yielding to the caller.

### Additional features

- **Output validation** — fluent predicate-based assertions on agent responses
- **Custom rules** — implement `IGuardrailRule` to add your own checks with full access to the conversation context
- **Composable middleware** — all rules run as MAF middleware; stack them, order them, short-circuit them
- **Fully testable** — every rule is a pure function; mock the pipeline, assert the behavior
- **Offline-first** — works without any cloud services; optionally upgrade to Azure AI Content Safety or LLM-based rules for production accuracy

## Packages

| Package | Description | NuGet |
|---------|-------------|-------|
| `AgentGuard.Core` | Core abstractions, rules engine, fluent builder, LLM rules, MAF middleware | [![NuGet](https://img.shields.io/nuget/v/AgentGuard.Core.svg)](https://www.nuget.org/packages/AgentGuard.Core) |
| `AgentGuard.Local` | Offline classifiers (keyword similarity for topic boundary) | [![NuGet](https://img.shields.io/nuget/v/AgentGuard.Local.svg)](https://www.nuget.org/packages/AgentGuard.Local) |
| `AgentGuard.Azure` | Azure AI Content Safety integration | [![NuGet](https://img.shields.io/nuget/v/AgentGuard.Azure.svg)](https://www.nuget.org/packages/AgentGuard.Azure) |
| `AgentGuard.Hosting` | DI registration and named policy factory | [![NuGet](https://img.shields.io/nuget/v/AgentGuard.Hosting.svg)](https://www.nuget.org/packages/AgentGuard.Hosting) |

## Quick Start

### Install

```bash
dotnet add package AgentGuard.Core --prerelease
```

### Basic Usage (regex-based, offline)

```csharp
using Microsoft.Agents.AI;
using AgentGuard.Core.Middleware;
using AgentGuard.Core.Rules.PII;
using AgentGuard.Core.Rules.PromptInjection;

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
using AgentGuard.Core.Middleware;
using AgentGuard.Core.Rules.LLM;

// Use any IChatClient — Azure OpenAI, Ollama, etc.
IChatClient classifier = new OllamaChatClient("llama3");

var guardedAgent = agent
    .AsBuilder()
    .UseAgentGuard(g => g
        .BlockPromptInjection()                                // regex: fast first pass
        .BlockPromptInjectionWithLlm(classifier)               // LLM: catches what regex misses
        .DetectPIIWithLlm(classifier)                          // LLM: catches names, addresses, etc.
        .EnforceTopicBoundaryWithLlm(classifier, "billing")    // LLM: semantic topic matching
        .LimitInputTokens(4000)
    )
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

### Custom Rules

```csharp
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

// Register it
var guardedAgent = agent.AsBuilder()
    .UseAgentGuard(g => g.AddRule(new NoProfanityRule()))
    .Build();
```

## Architecture

```
User Input
    │
    ▼
┌─────────────────────────────┐
│  Input Guardrails Pipeline  │
│  ┌───────────────────────┐  │
│  │ Prompt Injection      │  │  ← Regex (order 10) + LLM (order 15)
│  ├───────────────────────┤  │
│  │ PII Detection         │  │  ← Regex (order 20) + LLM (order 25)
│  ├───────────────────────┤  │
│  │ Topic Boundary        │  │  ← Keywords (order 30) + LLM (order 35)
│  ├───────────────────────┤  │
│  │ Token Limit Check     │  │  ← order 40
│  ├───────────────────────┤  │
│  │ Content Safety        │  │  ← order 50
│  └───────────────────────┘  │
└─────────────┬───────────────┘
              │
              ▼
     MAF Agent (LLM call)
       RunAsync / RunStreamingAsync
              │
              ▼
┌─────────────────────────────┐
│  Output Guardrails Pipeline │
│  ┌───────────────────────┐  │
│  │ PII Redaction         │  │  ← Catches LLM-generated PII
│  ├───────────────────────┤  │
│  │ Content Safety Filter │  │  ← Blocks harmful content
│  ├───────────────────────┤  │
│  │ Output Validation     │  │  ← Custom assertions
│  ├───────────────────────┤  │
│  │ Token Limit Check     │  │  ← Enforces response budget
│  └───────────────────────┘  │
└─────────────┬───────────────┘
              │
              ▼
        User Response
```

## Rule Execution Order

Rules execute in order of their `Order` property (lower = first). Built-in rules are ordered to maximize efficiency — cheap regex checks run before expensive LLM calls:

| Order | Rule | Type | Phase |
|-------|------|------|-------|
| 10 | `PromptInjectionRule` | Regex | Input |
| 15 | `LlmPromptInjectionRule` | LLM | Input |
| 20 | `PiiRedactionRule` | Regex | Both |
| 25 | `LlmPiiDetectionRule` | LLM | Both |
| 30 | `TopicBoundaryRule` | Keywords | Input |
| 35 | `LlmTopicGuardrailRule` | LLM | Input |
| 40 | `TokenLimitRule` | Local | Input/Output |
| 50 | `ContentSafetyRule` | Pluggable | Both |
| 100 | Custom rules | User-defined | Any |

## Samples

- [Basic Guardrails](samples/BasicGuardrails/) — minimal setup with common rules
- [Custom Rules](samples/CustomRules/) — implementing and composing custom guardrail rules
- [Azure Integration](samples/AzureIntegration/) — using Azure AI Content Safety for production
- [Workflow Guardrails](samples/WorkflowGuardrails/) — applying guardrails to multi-agent MAF workflows

## Documentation

- [Getting Started](docs/getting-started.md)
- [Rule Reference](docs/rules-reference.md)
- [Custom Rules Guide](docs/custom-rules.md)
- [Configuration](docs/configuration.md)
- [Azure Integration](docs/azure-integration.md)

## Requirements

- .NET 8.0 or later
- Microsoft Agent Framework 1.0.0-rc4 or later

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.
