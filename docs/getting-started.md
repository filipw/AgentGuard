# Getting Started with AgentGuard

## Installation

```bash
dotnet add package AgentGuard.Core --prerelease
dotnet add package AgentGuard.AgentFramework --prerelease  # optional: MAF middleware integration
dotnet add package AgentGuard.Workflows --prerelease       # optional: MAF workflow executor guardrails
dotnet add package AgentGuard.Onnx --prerelease            # optional: ONNX ML-based classifiers
dotnet add package AgentGuard.Local --prerelease           # optional: offline classifiers
dotnet add package AgentGuard.Azure --prerelease           # optional: Azure AI Content Safety
dotnet add package AgentGuard.Hosting --prerelease         # optional: DI + config binding
```

## Your First Guardrail

AgentGuard's core engine is framework-agnostic — use it standalone without any agent framework dependency:

```csharp
using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Builders;
using AgentGuard.Core.Guardrails;
using Microsoft.Extensions.Logging.Abstractions;

var policy = new GuardrailPolicyBuilder()
    .BlockPromptInjection()
    .RedactPII()
    .Build();

var pipeline = new GuardrailPipeline(policy, NullLogger<GuardrailPipeline>.Instance);

var ctx = new GuardrailContext { Text = userInput, Phase = GuardrailPhase.Input };
var result = await pipeline.RunAsync(ctx);

if (result.IsBlocked)
    Console.WriteLine($"Blocked: {result.BlockingResult!.Reason}");
else if (result.WasModified)
    Console.WriteLine($"Redacted: {result.FinalText}");
```

### With Microsoft Agent Framework

Add the `AgentGuard.AgentFramework` package to integrate as MAF middleware:

```csharp
using AgentGuard.AgentFramework;

var guardedAgent = agent
    .AsBuilder()
    .UseAgentGuard(g => g.BlockPromptInjection().RedactPII())
    .Build();
```

The agent now blocks injection attempts and redacts PII before the LLM sees it.

## How It Works

1. **Input guardrails** — injection check, PII redaction, topic enforcement, token limits
2. **Agent runs** — processes the (potentially modified) input
3. **Output guardrails** — content safety, PII in responses, output validation

If any rule blocks, the agent never runs. The user gets a configurable rejection message.

## Available Rules

| Rule | Phase | Order | Package |
|------|-------|-------|---------|
| `NormalizeInput()` | Input | 5 | Core |
| `BlockPromptInjection()` | Input | 10 | Core |
| `BlockPromptInjectionWithOnnx()` | Input | 12 | Onnx |
| `BlockPromptInjectionWithLlm()` | Input | 15 | Core |
| `RedactPII()` | Both | 20 | Core |
| `DetectPIIWithLlm()` | Both | 25 | Core |
| `EnforceTopicBoundary()` | Input | 30 | Core |
| `EnforceTopicBoundaryWithLlm()` | Input | 35 | Core |
| `LimitInputTokens()` / `LimitOutputTokens()` | Input/Output | 40 | Core |
| `BlockHarmfulContent()` | Both | 50 | Core + Azure |
| `EnforceOutputPolicy()` | Output | 55 | Core |
| `EnforceOutputTopicBoundary()` | Output | 60 | Core |
| `CheckGroundedness()` | Output | 65 | Core |
| `CheckCopyright()` | Output | 75 | Core |
| `ValidateInput()` / `ValidateOutput()` | Input/Output | 100 | Core |

## Workflow Guardrails

For MAF workflows with multiple `Executor` steps, use `AgentGuard.Workflows` to apply guardrails at step boundaries:

```csharp
using AgentGuard.Workflows;

var guardedExecutor = myExecutor.WithGuardrails(b => b
    .BlockPromptInjection()
    .RedactPII());

try
{
    await guardedExecutor.HandleAsync(input, workflowContext);
}
catch (GuardrailViolationException ex)
{
    // Guardrail blocked — ex.Phase, ex.ExecutorId, ex.ViolationResult
}
```

## Next Steps

- [Rule Reference](rules-reference.md) — every option for every built-in rule
- [Custom Rules Guide](custom-rules.md) — build your own rules
- [Configuration](configuration.md) — DI, named policies
- [Azure Integration](azure-integration.md) — production content safety
