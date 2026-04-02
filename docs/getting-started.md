# Getting Started with AgentGuard

## Installation

```bash
dotnet add package AgentGuard --prerelease                 # core + Defender ONNX model + offline classifiers
dotnet add package AgentGuard.AgentFramework --prerelease  # optional: MAF middleware + workflow guardrails
dotnet add package AgentGuard.Azure --prerelease           # optional: Azure AI Content Safety
dotnet add package AgentGuard.Hosting --prerelease         # optional: DI + config binding
dotnet add package AgentGuard.RemoteClassifier --prerelease # optional: remote ML classifier via HTTP
```

## Your First Guardrail

The fastest way to get started is `UseDefaults()`, which wires up a solid baseline that works fully offline - input normalization, regex + Defender ML prompt injection detection, PII redaction, secrets detection, and tool call/result guardrails:

```csharp
using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Builders;
using AgentGuard.Core.Guardrails;
using AgentGuard.Onnx;
using Microsoft.Extensions.Logging.Abstractions;

var policy = new GuardrailPolicyBuilder()
    .UseDefaults()
    .Build();

var pipeline = new GuardrailPipeline(policy, NullLogger<GuardrailPipeline>.Instance);

var ctx = new GuardrailContext { Text = userInput, Phase = GuardrailPhase.Input };
var result = await pipeline.RunAsync(ctx);

if (result.IsBlocked)
    Console.WriteLine($"Blocked: {result.BlockingResult!.Reason}");
else if (result.WasModified)
    Console.WriteLine($"Redacted: {result.FinalText}");
```

You can also pick and choose individual rules:

```csharp
var policy = new GuardrailPolicyBuilder()
    .BlockPromptInjection()
    .RedactPII()
    .EnforceTopicBoundary("billing", "returns")
    .LimitInputTokens(4000)
    .Build();
```

### With Microsoft Agent Framework

Add the `AgentGuard.AgentFramework` package to integrate as MAF middleware:

```csharp
using AgentGuard.AgentFramework;
using AgentGuard.Onnx;

var guardedAgent = agent
    .AsBuilder()
    .UseAgentGuard(g => g.UseDefaults())
    .Build();
```

Or pick specific rules:

```csharp
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

## How It Works

1. **Input guardrails** - injection check, PII redaction, topic enforcement, token limits
2. **Agent runs** - processes the (potentially modified) input
3. **Output guardrails** - content safety, PII in responses, output validation

If any rule blocks, the agent never runs. The user gets a configurable rejection message.

## Available Rules

| Rule | Phase | Order | Package |
|------|-------|-------|---------|
| `NormalizeInput()` | Input | 5 | Core |
| `BlockPromptInjection()` | Input | 10 | Core |
| `BlockPromptInjectionWithDefender()` | Input | 11 | Onnx |
| `BlockPromptInjectionWithDeberta()` | Input | 12 | Onnx |
| `BlockPromptInjectionWithRemoteClassifier()` | Input | 13 | RemoteClassifier |
| `BlockPromptInjectionWithAzurePromptShield()` | Input | 14 | Azure |
| `BlockPromptInjectionWithLlm()` | Input | 15 | Core |
| `DetectSecrets()` | Both | 22 | Core |
| `RedactPII()` | Both | 20 | Core |
| `DetectPIIWithLlm()` | Both | 25 | Core |
| `EnforceTopicBoundary()` | Input | 30 | Core |
| `EnforceTopicBoundaryWithLlm()` | Input | 35 | Core |
| `LimitInputTokens()` / `LimitOutputTokens()` | Input/Output | 40 | Core |
| `GuardToolCalls()` | Output | 45 | Core |
| `GuardToolResults()` | Output | 47 | Core |
| `BlockHarmfulContent()` | Both | 50 | Core + Azure |
| `EnforceOutputPolicy()` | Output | 55 | Core |
| `EnforceOutputTopicBoundary()` | Output | 60 | Core |
| `CheckGroundedness()` | Output | 65 | Core |
| `CheckCopyright()` | Output | 75 | Core |
| `ValidateInput()` / `ValidateOutput()` | Input/Output | 100 | Core |

## Workflow Guardrails

For MAF workflows with multiple `Executor` steps, use `AgentGuard.AgentFramework` to apply guardrails at step boundaries:

```csharp
using AgentGuard.AgentFramework.Workflows;

var guardedExecutor = myExecutor.WithGuardrails(b => b
    .BlockPromptInjection()
    .RedactPII());

try
{
    await guardedExecutor.HandleAsync(input, workflowContext);
}
catch (GuardrailViolationException ex)
{
    // Guardrail blocked - ex.Phase, ex.ExecutorId, ex.ViolationResult
}
```

## Re-ask / Self-healing (Experimental)

> **Note:** This feature is experimental. It currently supports non-streaming pipelines only.
> Streaming re-ask support is planned for a future release.

When output guardrails block a response, you can opt in to re-ask: the pipeline re-prompts the LLM with the failure reason and re-evaluates all output rules on the new response.

```csharp
var policy = new GuardrailPolicyBuilder()
    .EnforceOutputPolicy(chatClient, "Never recommend competitors")
    .CheckGroundedness(chatClient)
    .EnableReask(chatClient, o =>
    {
        o.MaxAttempts = 2;           // retry up to 2 times (default: 1)
        o.IncludeBlockedResponse = true; // show LLM what to avoid (default: true)
    })
    .Build();

var pipeline = new GuardrailPipeline(policy, NullLogger<GuardrailPipeline>.Instance);

var result = await pipeline.RunAsync(outputContext);

if (result.WasReasked)
    Console.WriteLine($"Self-healed after {result.ReaskAttemptsUsed} attempt(s)");
```

Re-ask only triggers for output-phase blocks - input guardrails always short-circuit immediately.

## Observability (OpenTelemetry)

AgentGuard emits OpenTelemetry-compatible spans and metrics out of the box. Register the `ActivitySource` and `Meter` with your OTel pipeline:

```csharp
using AgentGuard.Hosting;

builder.Services.AddOpenTelemetry()
    .WithTracing(t => t.AddAgentGuardInstrumentation())
    .WithMetrics(m => m.AddAgentGuardInstrumentation());
```

Or without the Hosting package:

```csharp
builder.Services.AddOpenTelemetry()
    .WithTracing(t => t.AddSource("AgentGuard"))
    .WithMetrics(m => m.AddMeter("AgentGuard"));
```

Every pipeline run, rule evaluation, re-ask attempt, and streaming retraction is traced. See the [Observability docs](observability.md) for the full span and metric reference.

## Next Steps

- [Rule Reference](rules-reference.md) - every option for every built-in rule
- [Custom Rules Guide](custom-rules.md) - build your own rules
- [Configuration](configuration.md) - DI, named policies
- [Observability](observability.md) - spans, metrics, and sensitive data
- [Azure Integration](azure-integration.md) - production content safety
