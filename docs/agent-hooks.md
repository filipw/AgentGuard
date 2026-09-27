# Agent-Hooks Enforcement (preview)

[Agent-Hooks](https://github.com/responsibleai/agent-hooks) (AGENT-HOOKS-0.1) is a framework-neutral contract for intercepting an agent run at fixed points: the input, each model call, each tool call and tool result, and the output. At each point the host asks its interceptors for a verdict - allow, deny or transform - and doesn't go on until it has one. The Microsoft Agent Framework supports it through the `Microsoft.Agents.AI.AgentHooks` package.

`AgentGuard.AgentHooks` runs an AgentGuard policy as an Agent-Hooks interceptor. It ships as a prerelease (`-alpha`), because the Agent-Hooks packages it depends on are alpha and NuGet doesn't let a stable package depend on a prerelease one.

```bash
dotnet add package AgentGuard.AgentHooks --prerelease
```

## Agent-Hooks or `UseAgentGuard()`

Both enforce the same policies, with the same rules. What differs is where they sit in the agent.

| | `UseAgentGuard()` on `AIAgentBuilder` | `AsAIAgentWithAgentGuard()` (Agent-Hooks) |
|---|---|---|
| Where checks run | Around the agent run, plus a function-invocation middleware for tool calls and results | At every interception point inside the run, including before and after each model call |
| History | The agent saves its response before outer middleware sees it; the middleware repairs the default in-memory history afterwards | Nothing is saved until the output verdict, whatever history provider the agent uses |
| Streaming | Buffered or progressive | Buffered |
| Agents | Any `AIAgent` | Agents built from an `IChatClient` by the factory |
| Maturity | Stable dependencies | Alpha dependencies and a native library (see [Limitations](#limitations)) |

Use one or the other on an agent, not both.

## Usage

```csharp
using AgentGuard.AgentHooks;
using AgentGuard.Pii;
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;

var agent = chatClient.AsAIAgentWithAgentGuard(
    g => g
        .BlockPromptInjection()
        .RedactPii()
        .GuardToolCalls()
        .GuardToolResults()
        .OnViolation(v => v.RejectWithMessage("Sorry, I can't help with that.")),
    new ChatClientAgentOptions
    {
        Name = "support",
        ChatOptions = new ChatOptions { Instructions = "You are a support agent.", Tools = [lookupOrders] }
    });

var session = await agent.CreateSessionAsync();
var response = await agent.RunAsync("How many open orders do I have?", session);
```

Pass the chat client without a function-invocation loop (no `UseFunctionInvocation()`): the factory adds its own, so that each tool call and result goes through the interception points. A second overload takes an `IGuardrailPolicy` you built; the agent doesn't dispose that one. The last parameter, `services`, is passed on to the agent, and a registered `IGuardrailLedger` and `ILoggerFactory` are used when the options don't set a ledger or logger.

The [sample](../samples/AgentHooksGuardrails/) runs every scenario on this page offline, against a scripted model.

## What each interception point checks

| Point | What the policy checks | On a block |
|---|---|---|
| `input` | The input rules, over every user message of the request, as `UseAgentGuard()` does | The run ends with the violation message; the model is never called |
| `pre_model_call` | Opt-in (`GuardModelInput`): the user and system messages of each model request - history loaded from a store, text a context provider added. Each distinct text is judged once. | The message is replaced with `[message removed by guardrail policy]` and the call goes ahead |
| `post_model_call` | The calls and results of tools the model service ran itself (the host never runs them); with `ToolCallBlocking.StopRun`, the tool calls the response asks the host to run | The run ends with the violation message |
| `pre_tool_call` | Each tool call's arguments, just before the tool runs (the default, `ToolCallBlocking.ContinueWithToolError`) | The tool doesn't run; the model gets `BlockedToolCallMessage` as the call's error and carries on |
| `post_tool_call` | With `GuardToolResults()` in the policy: the text rules (PII, secrets) rewrite the result, then the tool-result rule inspects it | The model gets `BlockedToolResultMessage` instead of the result |
| `output` | The output rules, over each assistant message of the response and its reasoning. Its tool calls and results were checked at the points above. | The run ends with the violation message; nothing of the run is saved |

A rewrite (PII redaction, for example) is a transform: the rewritten content replaces the original in the run from that point on, and in what the agent saves. Messages the rules leave alone are handed back as they came, so the host keeps the originals, metadata and all. A JSON tool result that a rule rewrites goes back to the model as JSON.

## What the caller sees on a block

By default (`ViolationBehavior.Respond`) a blocked run returns an ordinary response whose text is the violation message, and nothing of the run is saved to the session's history. The Agent-Hooks `InterceptionRecord` of the blocking verdict is in the response's `AdditionalProperties`:

```csharp
if (response.AdditionalProperties?.TryGetValue(AgentGuardAgentHooksExtensions.InterceptionRecordKey, out var value) == true &&
    value is InterceptionRecord record)
{
    Console.WriteLine($"{record.Verdict.Reason} at {record.InterceptionPoint.ToWireName()}");  // agentguard:prompt-injection at input
}
```

A streamed run that is blocked yields the violation message as its only update; streaming is buffered, so nothing of the blocked run went out before it. With `ViolationBehavior.Throw`, the run throws `InterceptionBlockedException` instead, as Agent-Hooks does on its own. A failure of the enforcement itself - an interceptor that throws or times out - always throws, whatever the setting: Agent-Hooks fails closed with a `host_error:*` verdict.

Each AgentGuard deny carries `rule:<rule>` and `severity:<severity>` result labels. Its reason is `agentguard:<rule>`, except at the two tool points, where the host passes the verdict on to the model: there the reason is `agentguard:blocked` and the message the neutral placeholder, so the model isn't told which check fired.

## Tool calls: carry on or stop

`ToolCallBlocking` decides where the tool-call rules check a tool the host runs:

- `ContinueWithToolError` (the default) - each call is checked at `pre_tool_call`. A blocked call never runs, the model receives `BlockedToolCallMessage` as the call's error, and the loop continues, so the model can answer without the tool or try something else.
- `StopRun` - the calls a model response asks for are checked together at `post_model_call`, before any of them runs, and a block ends the run.

Tools the model service runs itself (hosted tools) are checked at `post_model_call` in either mode. They have run by then and the model has used their results, so a block ends the run, and a rewrite of their results isn't applied.

## Shadow mode

`EnforcementMode.EvaluateOnly` lets every run through unchanged - no denies, no rewrites - while each evaluation is still recorded. Together with a [decision ledger](observability.md#tamper-evident-decision-ledger), it shows what a policy would do before you enforce it:

```csharp
using var ledger = new HashChainLedger();

var agent = chatClient.AsAIAgentWithAgentGuard(
    g => g.BlockPromptInjection().RedactPii(),
    configureHooks: o =>
    {
        o.Mode = EnforcementMode.EvaluateOnly;
        o.Ledger = ledger;
    });

await agent.RunAsync(userMessage);

foreach (var entry in ledger.Entries)
    Console.WriteLine($"{entry.Decision.Stage} {entry.Decision.Outcome} {entry.Decision.BlockingRuleName}");
```

Each decision records the interception point it was made at in `GuardrailDecision.Stage` (`input`, `pre_tool_call`, `output` and so on).

## Options

`configureHooks` sets `AgentGuardHooksOptions`:

| Option | Default | Description |
|---|---|---|
| `GuardModelInput` | `false` | Check the user and system messages of each model request at `pre_model_call` |
| `ToolCallBlocking` | `ContinueWithToolError` | Where tool calls are checked, and whether a block ends the run |
| `ToolResultRuleOrders` | 20, 22, 25, 47 | Orders of the output rules that run on each tool result: PII, secrets, LLM PII and the tool-result rule |
| `BlockedToolCallMessage` | `[blocked: tool call violated guardrail policy]` | The error the model receives for a blocked tool call |
| `BlockedToolResultMessage` | `[blocked: tool result violated guardrail policy]` | What the model receives in place of a blocked tool result |
| `EscalateWhen` | none | Which blocks become an escalation, a deny an approval `Resolver` can lift |
| `Ledger` | none | Decision ledger; each decision records its interception point as `Stage` |
| `Logger` | none | Logger for the guardrail pipelines |
| `ViolationBehavior` | `Respond` | Return the violation message, or throw `InterceptionBlockedException` |
| `Mode` | `Enforce` | `EvaluateOnly` records verdicts without enforcing them |
| `Timeout` | 30 seconds | How long the interceptor may take at one point. A timeout is a deny, so it has to cover the slowest rule, such as an LLM judge. `null` uses the Agent-Hooks default of 5 seconds. |
| `Resolver` | none | Approval resolver for escalations |
| `Composition`, `IdentityProvider`, `RecordSink` | Agent-Hooks defaults | Passed through to Agent-Hooks: how several interceptors' verdicts combine, how records identify content, and a callback for every interception record |
| `AdditionalInterceptors` | empty | Other interceptors to run after AgentGuard's |

## Other hosts

`AgentGuardInterceptor` is a plain Agent-Hooks `IInterceptor`, so it can be registered with any Agent-Hooks host, or with the Agent Framework's factory directly, next to other interceptors:

```csharp
var interceptor = new AgentGuardInterceptor(policy, new AgentGuardInterceptorOptions { Ledger = ledger });

var agent = chatClient.AsAIAgentWithAgentHooks(
    new AgentHooksOptions().AddInterceptor(interceptor, "agentguard"));
```

Registered this way, a block throws `InterceptionBlockedException`; `ViolationBehavior` belongs to `AsAIAgentWithAgentGuard()`. The interceptor is safe to share across agents and concurrent runs. It keeps the conversation each run started from, for the rules at the later points, for up to 1,024 sessions at a time.

## Observability

Each interception point the interceptor handles is an `agentguard.hooks.<point>` span (for example `agentguard.hooks.pre_tool_call`) with the `agentguard.hooks.point`, `agentguard.policy.name`, `agentguard.agent.name` and `agentguard.outcome` tags, plus `agentguard.blocked.reason` and `agentguard.severity` on a block. The pipeline and rule spans nest under it. See [Observability](observability.md).

## Limitations

- **Preview.** `Microsoft.Agents.AI.AgentHooks` and `ResponsibleAI.AgentHooks` are alpha, and their APIs may change.
- **Platforms.** `ResponsibleAI.AgentHooks` wraps a native library shipped for linux-x64, osx-x64, osx-arm64 and win-x64. Other platforms, such as linux-arm64 containers, aren't supported.
- **Not a security boundary.** Agent-Hooks is a cooperative contract: it trusts the host process and the code the agent runs in.
- **Buffered streaming.** Progressive streaming (`UseProgressiveStreaming()`) doesn't apply; a streamed run is released after the output verdict.
- **Service-side history.** When the model service keeps the conversation (a `ConversationId`), it stores each turn before any verdict.
- **Hosted tools.** Tools the service runs are checked after the model call that ran them (see above). Only function calls and results are inspected; other hosted tool content (MCP server calls, code interpreter, web search) isn't.
- **Agent construction.** The factory rejects a chat client that already has a function-invocation loop and `UseProvidedChatClientAsIs`, and a run rejects a per-run `ChatClientFactory`.
- **Configuration.** The agent is built in code; there is no `appsettings.json` or `IAgentGuardFactory` support yet.
