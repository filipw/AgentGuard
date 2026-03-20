# Getting Started with AgentGuard

## Installation

```bash
dotnet add package AgentGuard.Core --prerelease
dotnet add package AgentGuard.Workflows --prerelease # optional: workflow executor guardrails
dotnet add package AgentGuard.Local --prerelease     # optional: offline classifiers
dotnet add package AgentGuard.Azure --prerelease     # optional: Azure AI Content Safety
dotnet add package AgentGuard.Hosting --prerelease   # optional: DI + config binding
```

## Your First Guardrail

```csharp
using AgentGuard.Core.Middleware;

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

| Rule | Phase | Order |
|------|-------|-------|
| `BlockPromptInjection()` | Input | 10 |
| `RedactPII()` | Both | 20 |
| `EnforceTopicBoundary()` | Input | 30 |
| `LimitInputTokens()` / `LimitOutputTokens()` | Input/Output | 40 |
| `BlockHarmfulContent()` | Both | 50 |
| `ValidateInput()` / `ValidateOutput()` | Input/Output | 100 |

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
