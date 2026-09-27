# Observability (OpenTelemetry)

AgentGuard emits OpenTelemetry-compatible spans and metrics for guardrail pipeline evaluations. All instrumentation uses `System.Diagnostics.Activity` and `System.Diagnostics.Metrics` - no hard dependency on the OpenTelemetry SDK in core packages. You bring your own exporter.

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
| `agentguard.pipeline.run` | Full pipeline evaluation | `agentguard.policy.name`, `agentguard.phase`, `agentguard.outcome`, `agentguard.agent.name`; on a block also `agentguard.blocked.reason` and `agentguard.severity` |
| `agentguard.rule.evaluate {name}` | Individual rule evaluation | `agentguard.rule.name`, `agentguard.phase`, `agentguard.rule.order`, `agentguard.outcome`; on a block also `agentguard.blocked.reason` and `agentguard.severity`, on a rule error `error.type`. Rule spans from progressive streaming also carry `agentguard.streaming.strategy` |
| `agentguard.pipeline.reask` | Re-ask loop | `agentguard.policy.name`, `agentguard.reask.max_attempts`, `agentguard.reask.attempts_used`, `agentguard.outcome`; when the attempts run out also `agentguard.blocked.reason` and `agentguard.severity` |
| `agentguard.streaming.pipeline` | Progressive streaming evaluation | `agentguard.policy.name`, `agentguard.outcome`, `agentguard.streaming.progressive_rules`, `agentguard.streaming.final_only_rules`, `agentguard.streaming.adaptive_rules`; on a block also `agentguard.blocked.reason` and `agentguard.severity` |

### AgentFramework middleware spans

| Span name | Description | Key tags |
|-----------|-------------|----------|
| `agentguard.middleware.input` | MAF input guardrails | `agentguard.agent.name`, `agentguard.phase`, `agentguard.outcome`; on a block also `agentguard.blocked.reason` and `agentguard.severity` |
| `agentguard.middleware.output` | MAF output guardrails (also emitted under `agentguard.middleware.streaming` for buffered streaming) | `agentguard.agent.name`, `agentguard.phase`, `agentguard.outcome`, `agentguard.tool_call.count`; on a block also `agentguard.blocked.reason` and `agentguard.severity` |
| `agentguard.middleware.streaming` | MAF streaming guardrails | `agentguard.agent.name`, `agentguard.streaming.strategy`, `agentguard.outcome` (the outcome of the whole streamed run: blocked on an input or output block, otherwise modified or passed); on a block also `agentguard.blocked.reason` and `agentguard.severity` |
| `agentguard.executor.guard` | Workflow executor guardrails (`agentguard.executor.guard input` / `agentguard.executor.guard output` for executors with a typed output) | `agentguard.executor.id`, `agentguard.phase`, `agentguard.message.type`, `agentguard.outcome`; on a block also `agentguard.blocked.reason` and `agentguard.severity` |

### Agent-Hooks spans

| Span name | Description | Key tags |
|-----------|-------------|----------|
| `agentguard.hooks.<point>` | One Agent-Hooks interception point handled by `AgentGuardInterceptor` (`agentguard.hooks.input`, `agentguard.hooks.pre_tool_call`, `agentguard.hooks.output` and so on); the pipeline and rule spans of its evaluations nest under it | `agentguard.hooks.point`, `agentguard.policy.name`, `agentguard.agent.name`, `agentguard.outcome`; on a block also `agentguard.blocked.reason` and `agentguard.severity`; when the interceptor throws, `error.type` |

### Span hierarchy

When using the MAF middleware, spans nest naturally under the existing MAF agent invocation span:

```
invoke_agent (MAF)
  └─ agentguard.middleware.input
       └─ agentguard.pipeline.run
            ├─ agentguard.rule.evaluate prompt-injection
            ├─ agentguard.rule.evaluate defender-prompt-injection
            └─ agentguard.rule.evaluate pii
  └─ agentguard.middleware.output
       └─ agentguard.pipeline.run
            ├─ agentguard.rule.evaluate tool-call-guardrail
            └─ agentguard.rule.evaluate content-safety
```

Rule spans are named after the rule's `Name` (`prompt-injection`, `pii`, `tool-call-guardrail`, and so on). The adapters run the pipeline once per message they evaluate: `agentguard.middleware.input` holds one `agentguard.pipeline.run` for the newest user message plus one for each earlier user message whose verdict is not cached yet, and `agentguard.middleware.output` holds one per assistant message of the response. When a MAF policy has tool rules, each tool invocation adds pipeline runs under the sub-policy names `<policy>.tool-calls`, `<policy>.tool-results.text` and `<policy>.tool-results` (in the `agentguard.policy.name` tag).

### Span status

A block is an expected outcome of a policy, not a failure, so error-rate alerts built on span status don't fire on policy decisions:

- A blocked span records the block in `agentguard.outcome` = `blocked`, plus `agentguard.blocked.reason` and `agentguard.severity` where listed above, and leaves the span status unset. This includes running out of re-ask attempts.
- Blocked rule spans from `GuardrailPipeline` also include an `agentguard.rule.blocked` event with `reason` and `severity` tags.
- A rule that could not reach a verdict (a result with `IsError`) sets `ActivityStatusCode.Error` on its rule span, with the error detail in `error.type` and the status description. This applies whatever its `ErrorBehavior` did with the text, so a fail-open error is still visible.
- An exception that escapes a rule, a pipeline run, a re-ask or a streaming evaluation sets `ActivityStatusCode.Error` on that span, with the exception type in `error.type`. Cancellation through the caller's token is not recorded as an error.
- The MAF middleware, Agent-Hooks and workflow executor spans follow the same rules: a block sets the outcome, reason and severity tags; an exception sets `ActivityStatusCode.Error`. A middleware or Agent-Hooks span also sets it when the block came from a rule that could not reach a verdict and failed closed.

## Metrics

| Metric name | Type | Unit | Description |
|-------------|------|------|-------------|
| `agentguard.pipeline.evaluations` | Counter | - | Total pipeline runs. Tags: `agentguard.policy.name`, `agentguard.phase`, `agentguard.outcome` |
| `agentguard.rule.evaluations` | Counter | - | Total individual rule evaluations. Tags: `agentguard.rule.name`, `agentguard.phase`, `agentguard.outcome` |
| `agentguard.rule.blocks` | Counter | - | Rule evaluations that resulted in a block. Tags: `agentguard.rule.name`, `agentguard.severity` |
| `agentguard.pipeline.duration` | Histogram | ms | Pipeline execution duration. Tags: `agentguard.policy.name`, `agentguard.phase`, `agentguard.outcome` |
| `agentguard.rule.duration` | Histogram | ms | Per-rule execution duration. Tags: `agentguard.rule.name`, `agentguard.phase` |
| `agentguard.pipeline.reask.attempts` | Counter | - | Re-ask attempts. Tags: `agentguard.policy.name` |
| `agentguard.pipeline.modifications` | Counter | - | Text modifications (PII redaction, etc.). Tags: `agentguard.policy.name`, `agentguard.phase` (the progressive streaming pipeline records only `agentguard.policy.name`) |
| `agentguard.streaming.retractions` | Counter | - | Streaming retractions. Tags: `agentguard.policy.name` |

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
| `InterceptionPoint` | `agentguard.hooks.point` |
| `ErrorType` | `error.type` |

### Outcome values

| Value | Meaning |
|-------|---------|
| `passed` | All rules passed |
| `blocked` | A rule blocked the text |
| `modified` | A rule modified the text (e.g. PII redaction) |
| `error` | A rule could not reach a verdict and did not block (rule spans and `agentguard.rule.evaluations` only) |

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

When enabled, the pipeline span includes an `agentguard.input` event and, when no rule blocked, an `agentguard.output` event, each carrying a `text` tag with the input/output content.

## Aspire Dashboard Example

If you're using .NET Aspire, all AgentGuard spans and metrics appear automatically in the Aspire dashboard once registered in the service that runs the guardrails (for example in the ServiceDefaults OpenTelemetry setup, not in the AppHost):

```csharp
using AgentGuard.Hosting;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOpenTelemetry()
    .WithTracing(t => t.AddAgentGuardInstrumentation())
    .WithMetrics(m => m.AddAgentGuardInstrumentation());
```

You'll see guardrail pipeline runs as nested spans in the trace view, with per-rule durations and outcomes visible at a glance. The metrics view shows evaluation counts, block rates, and duration distributions.

## Tamper-evident decision ledger

Beyond traces and metrics, AgentGuard can keep a **tamper-evident audit trail** of pipeline decisions for compliance and forensics. Each decision (what policy was active, what was requested, and why it was allowed/blocked/modified) is stamped into a SHA-256 hash chain: every entry hashes its own fields together with the previous entry's hash, so any retroactive edit breaks the chain and is detected by `Verify()`.

The ledger types live in `AgentGuard.Core.Ledger` and are dependency-free (`System.Security.Cryptography` + `System.Text.Json`):

- `IGuardrailLedger` - append-only sink (`Append(GuardrailDecision)`).
- `GuardrailDecision` - the immutable decision facts (policy, phase, outcome, blocking rule/severity/reason, per-rule outcomes, input/output hashes, timestamp, and the `Stage` in the host where the evaluation ran - the interception point for Agent-Hooks, null elsewhere).
- `GuardrailLedgerEntry` - a chain record: the decision plus `Seq`, `PreviousHash`, and `Hash`.
- `HashChainLedger` - the concrete tamper-evident store: thread-safe append, optional append-only JSONL file mirror, `Verify()` (recompute and compare the entries held in memory), `Export()` (JSON of those entries), and `Load(path)` (re-hydrate a persisted JSONL chain so it can be re-verified after a process restart). A ledger constructed over an existing JSONL file continues its chain.

A decision is emitted once per pipeline evaluation, so every re-ask attempt is independently auditable. The adapters evaluate messages one at a time (each user message not answered from the verdict cache, each assistant message of a response), so a single request can add several entries.

### Enabling via Hosting

```csharp
using AgentGuard.Hosting;

builder.Services.AddAgentGuard(options =>
{
    options.DefaultPolicy(p => p.BlockPromptInjection());
    options.UseDecisionLedger();                       // in-memory hash chain
    // options.UseDecisionLedger("audit/decisions.jsonl"); // also mirror to JSONL
});
```

The ledger is registered as a singleton `IGuardrailLedger`. Two consumers resolve it from DI:

- the `GuardrailPipeline` that `AddAgentGuard` registers;
- the MAF agent middleware (`UseAgentGuard()` on `AIAgentBuilder`), from the service provider the agent is built with - build it with `.Build(serviceProvider)`, or pass the ledger to `UseAgentGuard(..., ledger: ledger)`.

The `IChatClient` decorator and workflow executors build their own pipelines and don't read DI, so hand them the ledger: `chatClient.UseAgentGuard(configure, ledger: ledger)` and `new GuardedExecutorOptions { Ledger = ledger }`. Resolve `IGuardrailLedger` (cast to `HashChainLedger`) anywhere to verify or export it.

`AddAgentGuard(IConfiguration)` has no ledger setting; register one yourself, for example `services.AddSingleton<IGuardrailLedger>(new HashChainLedger("audit/decisions.jsonl"))`, and the same resolution applies.

### Standalone

```csharp
using AgentGuard.Core.Ledger;
using AgentGuard.Core.Guardrails;

var ledger = new HashChainLedger();
var pipeline = new GuardrailPipeline(policy, logger, ledger);

// ... run the pipeline ...

bool intact = ledger.Verify();          // false if any entry was tampered with
string auditJson = ledger.Export();     // full chain as JSON
```

Decisions are recorded for both the buffered pipeline and the progressive **streaming** pipeline (each terminal outcome - passed, blocked mid-stream, or modified - is one entry).

### Verifying a persisted chain

When a ledger is configured with a JSONL file, the chain can be re-loaded and re-verified later (for example by an auditor on another machine). The stored hashes are preserved as-is, so tampering with any persisted line is detected:

```csharp
var loaded = HashChainLedger.Load("audit/decisions.jsonl");
if (!loaded.Verify(out var brokenAtSeq))
    Console.WriteLine($"chain broken at entry {brokenAtSeq}");
```

A ledger constructed over a JSONL file that already holds entries - as `UseDecisionLedger(path)` does on every process start - continues that chain. It reads only the file's last line, gives its first entry the next sequence number, and links that entry to the last entry's hash. The file therefore stays one chain that `Load` verifies from genesis, while the new ledger holds only the entries appended since (its `Verify()` checks that they link to the persisted tail). If the last line is not an intact entry (an interrupted write, or an edit), the constructor throws `InvalidDataException` naming the file instead of starting a second chain; `Load` throws the same exception, naming the line, for any bad line.

The loaded ledger is verification-only by default. Pass `resumeWriting: true` to keep appending to the same chain with every persisted entry also held in memory. The JSONL directory is created eagerly when the ledger is constructed, so the first append cannot fail on a missing directory.

### Failure isolation

The ledger is an audit **side-channel**: if recording a decision fails (for example a JSONL write error), the failure is logged and swallowed so it never breaks guardrail evaluation. The in-memory chain and the request both continue.

### What tamper-evidence covers

Editing an entry, or removing one from the middle of the chain, breaks the linkage and is reported
by `Verify()`. Removing entries from the **end** is not detectable: a hash chain carries no record of
how long it should be, so a truncated chain is indistinguishable from one that simply stopped there.
Detecting that needs an external anchor - the last sequence number recorded somewhere the chain's
holder cannot reach, or periodic publication of the head hash.

The in-memory chain is unbounded by default. For a long-lived service, pass a cap and mirror to a
file so the full chain is still on disk:

```csharp
options.UseDecisionLedger("audit/decisions.jsonl", maxInMemoryEntries: 10_000);
```

### Privacy

The ledger is **hash-only by default**: it records `InputHash` / `OutputHash` (SHA-256 of the text) but not the raw content. Raw `Input` / `Output` are captured only when content capture is enabled - the same `AgentGuardTelemetry.EnableSensitiveData` flag (env `AGENTGUARD_CAPTURE_CONTENT=true`) that gates span content. There is no separate toggle. When raw content is captured it is also bound into the hash chain, so tampering with the stored `Input` / `Output` (not just their hashes) is detected by `Verify()`.
