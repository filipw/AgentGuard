# Observability (OpenTelemetry)

AgentGuard emits OpenTelemetry-compatible spans and metrics for guardrail pipeline evaluations. All instrumentation uses `System.Diagnostics.Activity` and `System.Diagnostics.Metrics` — no hard dependency on the OpenTelemetry SDK in core packages. You bring your own exporter.

## Setup

### With AgentGuard.Hosting (recommended)

The `AgentGuard.Hosting` package includes convenience extensions that register the AgentGuard `ActivitySource` and `Meter` with OpenTelemetry:

```csharp
using AgentGuard.Hosting;

builder.Services.AddOpenTelemetry()
    .WithTracing(t => t
        .AddAgentGuardInstrumentation()   // registers ActivitySource "AgentGuard"
        .AddOtlpExporter())
    .WithMetrics(m => m
        .AddAgentGuardInstrumentation()   // registers Meter "AgentGuard"
        .AddOtlpExporter());
```

### Manual registration (no Hosting dependency)

If you don't use `AgentGuard.Hosting`, register the source and meter by name:

```csharp
builder.Services.AddOpenTelemetry()
    .WithTracing(t => t.AddSource("AgentGuard"))
    .WithMetrics(m => m.AddMeter("AgentGuard"));
```

## Telemetry Source

| Property | Value |
|----------|-------|
| ActivitySource name | `"AgentGuard"` |
| Meter name | `"AgentGuard"` |
| Central class | `AgentGuard.Core.Telemetry.AgentGuardTelemetry` |

## Spans

### Core pipeline spans

| Span name | Description | Key tags |
|-----------|-------------|----------|
| `agentguard.pipeline.run` | Full pipeline evaluation | `agentguard.policy.name`, `agentguard.phase`, `agentguard.outcome`, `agentguard.agent.name` |
| `agentguard.rule.evaluate {name}` | Individual rule evaluation | `agentguard.rule.name`, `agentguard.phase`, `agentguard.rule.order`, `agentguard.outcome` |
| `agentguard.pipeline.reask` | Re-ask loop | `agentguard.policy.name`, `agentguard.reask.max_attempts`, `agentguard.reask.attempts_used`, `agentguard.outcome` |
| `agentguard.streaming.pipeline` | Streaming pipeline evaluation | `agentguard.policy.name`, `agentguard.outcome` |

### AgentFramework middleware spans

| Span name | Description | Key tags |
|-----------|-------------|----------|
| `agentguard.middleware.input` | MAF input guardrails | `agentguard.agent.name`, `agentguard.phase`, `agentguard.outcome` |
| `agentguard.middleware.output` | MAF output guardrails | `agentguard.agent.name`, `agentguard.phase`, `agentguard.outcome`, `agentguard.tool_call.count` |
| `agentguard.middleware.streaming` | MAF streaming guardrails | `agentguard.agent.name`, `agentguard.streaming.strategy` |
| `agentguard.executor.guard` | Workflow executor guardrails | `agentguard.executor.id`, `agentguard.phase`, `agentguard.message.type`, `agentguard.outcome` |

### Span hierarchy

When using the MAF middleware, spans nest naturally under the existing MAF agent invocation span:

```
invoke_agent (MAF)
  └─ agentguard.middleware.input
       └─ agentguard.pipeline.run
            ├─ agentguard.rule.evaluate PromptInjectionRule
            ├─ agentguard.rule.evaluate DefenderPromptInjectionRule
            └─ agentguard.rule.evaluate PiiRedactionRule
  └─ agentguard.middleware.output
       └─ agentguard.pipeline.run
            ├─ agentguard.rule.evaluate ToolCallGuardrailRule
            └─ agentguard.rule.evaluate ContentSafetyRule
```

### Span status

- Pipeline and rule spans set `ActivityStatusCode.Error` when a rule blocks.
- The `StatusDescription` is set to the block reason.
- Blocked rule spans include an `agentguard.rule.blocked` event with `reason` and `severity` tags.

## Metrics

| Metric name | Type | Unit | Description |
|-------------|------|------|-------------|
| `agentguard.pipeline.evaluations` | Counter | — | Total pipeline runs. Tags: `agentguard.policy.name`, `agentguard.phase`, `agentguard.outcome` |
| `agentguard.rule.evaluations` | Counter | — | Total individual rule evaluations. Tags: `agentguard.rule.name`, `agentguard.phase`, `agentguard.outcome` |
| `agentguard.rule.blocks` | Counter | — | Rule evaluations that resulted in a block. Tags: `agentguard.rule.name`, `agentguard.severity` |
| `agentguard.pipeline.duration` | Histogram | ms | Pipeline execution duration. Tags: `agentguard.policy.name`, `agentguard.phase`, `agentguard.outcome` |
| `agentguard.rule.duration` | Histogram | ms | Per-rule execution duration. Tags: `agentguard.rule.name`, `agentguard.phase` |
| `agentguard.pipeline.reask.attempts` | Counter | — | Re-ask attempts. Tags: `agentguard.policy.name` |
| `agentguard.pipeline.modifications` | Counter | — | Text modifications (PII redaction, etc.). Tags: `agentguard.policy.name`, `agentguard.phase` |
| `agentguard.streaming.retractions` | Counter | — | Streaming retractions. Tags: `agentguard.policy.name` |

## Tag Keys

All tag keys are defined as constants in `AgentGuardTelemetry.Tags`:

| Constant | Tag key |
|----------|---------|
| `PolicyName` | `agentguard.policy.name` |
| `RuleName` | `agentguard.rule.name` |
| `Phase` | `agentguard.phase` |
| `Outcome` | `agentguard.outcome` |
| `Severity` | `agentguard.severity` |
| `AgentName` | `agentguard.agent.name` |
| `BlockedReason` | `agentguard.blocked.reason` |
| `RuleOrder` | `agentguard.rule.order` |
| `ExecutorId` | `agentguard.executor.id` |
| `MessageType` | `agentguard.message.type` |
| `StreamingStrategy` | `agentguard.streaming.strategy` |
| `ToolCallCount` | `agentguard.tool_call.count` |
| `ReaskMaxAttempts` | `agentguard.reask.max_attempts` |
| `ReaskAttemptsUsed` | `agentguard.reask.attempts_used` |

### Outcome values

| Value | Meaning |
|-------|---------|
| `passed` | All rules passed |
| `blocked` | A rule blocked the text |
| `modified` | A rule modified the text (e.g. PII redaction) |
| `error` | A rule encountered an error |

## Sensitive Data

By default, AgentGuard does **not** capture input/output text content in spans. To enable it:

```csharp
using AgentGuard.Core.Telemetry;

// programmatic opt-in
AgentGuardTelemetry.EnableSensitiveData = true;
```

Or via environment variable:

```bash
export AGENTGUARD_CAPTURE_CONTENT=true
```

When enabled, the pipeline span will include `agentguard.input` and `agentguard.output` events carrying a `text` tag with the input/output content.

## Aspire Dashboard Example

If you're using .NET Aspire, all AgentGuard spans and metrics appear automatically in the Aspire dashboard once registered:

```csharp
using AgentGuard.Hosting;

var builder = DistributedApplication.CreateBuilder(args);

builder.Services.AddOpenTelemetry()
    .WithTracing(t => t.AddAgentGuardInstrumentation())
    .WithMetrics(m => m.AddAgentGuardInstrumentation());
```

You'll see guardrail pipeline runs as nested spans in the trace view, with per-rule durations and outcomes visible at a glance. The metrics view shows evaluation counts, block rates, and duration distributions.
