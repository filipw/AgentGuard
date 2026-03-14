# AgentGuard

**Declarative guardrails and safety controls for Microsoft Agent Framework (.NET)**

[![NuGet](https://img.shields.io/nuget/v/AgentGuard.Core.svg)](https://www.nuget.org/packages/AgentGuard.Core)
[![Build](https://github.com/YOUR_USERNAME/AgentGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR_USERNAME/AgentGuard/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

What [NeMo Guardrails](https://github.com/NVIDIA/NeMo-Guardrails) and [Guardrails AI](https://github.com/guardrails-ai/guardrails) do for Python, **AgentGuard** does for .NET — with the fluent APIs, middleware integration, and type safety that .NET developers expect.

---

## Why AgentGuard?

Microsoft Agent Framework provides raw middleware hooks for intercepting agent runs, but every team ends up writing the same boilerplate: PII detection, prompt injection blocking, topic enforcement, token limits, output validation. AgentGuard provides all of this as composable, testable, declarative rules that plug directly into MAF's middleware pipeline.

```csharp
using AgentGuard.Core;

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

- **Prompt injection detection** — blocks jailbreak attempts, system prompt extraction, and role-play attacks using local classifiers (no cloud dependency)
- **PII redaction** — detects and redacts emails, phone numbers, SSNs, credit cards, addresses, and custom patterns on input and output
- **Topic boundary enforcement** — keeps agents on-task using embedding-based semantic similarity against allowed topic descriptors
- **Token limits** — enforces input/output token budgets with configurable overflow strategies (truncate, reject, summarize)
- **Output validation** — fluent predicate-based assertions on agent responses before they reach the user
- **Content safety** — severity-based filtering for hate, violence, sexual content, and self-harm (local or Azure AI Content Safety)
- **Custom rules** — implement `IGuardrailRule` to add your own checks with full access to the conversation context
- **Composable middleware** — all rules run as MAF middleware; stack them, order them, short-circuit them
- **Fully testable** — every rule is a pure function; mock the pipeline, assert the behavior
- **Offline-first** — works without any cloud services; optionally upgrade to Azure AI Content Safety for production

## Packages

| Package | Description | NuGet |
|---------|-------------|-------|
| `AgentGuard.Core` | Core abstractions, rules engine, fluent builder, MAF middleware | [![NuGet](https://img.shields.io/nuget/v/AgentGuard.Core.svg)](https://www.nuget.org/packages/AgentGuard.Core) |
| `AgentGuard.Local` | Offline classifiers for prompt injection, PII, topic boundary | [![NuGet](https://img.shields.io/nuget/v/AgentGuard.Local.svg)](https://www.nuget.org/packages/AgentGuard.Local) |
| `AgentGuard.Azure` | Azure AI Content Safety integration | [![NuGet](https://img.shields.io/nuget/v/AgentGuard.Azure.svg)](https://www.nuget.org/packages/AgentGuard.Azure) |
| `AgentGuard.Hosting` | DI registration, health checks, configuration binding | [![NuGet](https://img.shields.io/nuget/v/AgentGuard.Hosting.svg)](https://www.nuget.org/packages/AgentGuard.Hosting) |

## Quick Start

### Install

```bash
dotnet add package AgentGuard.Core --prerelease
dotnet add package AgentGuard.Local --prerelease  # for offline classifiers
```

### Basic Usage

```csharp
using Microsoft.Agents.AI;
using AgentGuard.Core;
using AgentGuard.Local;

// Create your MAF agent as usual
var agent = new AzureOpenAIClient(new Uri(endpoint), new AzureCliCredential())
    .GetChatClient("gpt-4o-mini")
    .AsAIAgent(instructions: "You are a helpful customer support agent.");

// Wrap it with guardrails
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
Console.WriteLine(await guardedAgent.RunAsync("What's the status of my order?"));
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
        .EnforceTopicBoundary("billing")
        .RequireOutputValidation(v => v.MaxLength(5000).NoMarkdown()));
});

// In agent registration
builder.AddAIAgent("SupportAgent", (sp, key) =>
{
    var chatClient = sp.GetRequiredService<IChatClient>();
    var guard = sp.GetRequiredService<IAgentGuardFactory>();

    return chatClient
        .AsAIAgent(name: key, instructions: "...")
        .AsBuilder()
        .UseAgentGuard(guard.GetPolicy("strict"))
        .Build();
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
        var text = context.Response?.Text ?? "";
        var hasProfanity = ProfanityDetector.Check(text);

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
│  │ Prompt Injection Check│  │  ← Blocks jailbreaks
│  ├───────────────────────┤  │
│  │ PII Redaction (Input) │  │  ← Redacts before LLM sees it
│  ├───────────────────────┤  │
│  │ Topic Boundary Check  │  │  ← Rejects off-topic
│  ├───────────────────────┤  │
│  │ Token Limit Check     │  │  ← Enforces budget
│  └───────────────────────┘  │
└─────────────┬───────────────┘
              │
              ▼
        MAF Agent (LLM)
              │
              ▼
┌─────────────────────────────┐
│  Output Guardrails Pipeline │
│  ┌───────────────────────┐  │
│  │ Content Safety Filter │  │  ← Blocks harmful content
│  ├───────────────────────┤  │
│  │ PII Redaction (Output)│  │  ← Catches LLM-generated PII
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
- Microsoft Agent Framework 1.0.0-rc1 or later

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.
