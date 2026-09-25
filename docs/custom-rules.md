# Custom Rules Guide

Implement `IGuardrailRule`:

```csharp
public class ProfanityFilter : IGuardrailRule
{
    private readonly HashSet<string> _blocked;
    public ProfanityFilter(IEnumerable<string> words) => _blocked = new(words, StringComparer.OrdinalIgnoreCase);

    public string Name => "profanity-filter";
    public GuardrailPhase Phase => GuardrailPhase.Both;

    public ValueTask<GuardrailResult> EvaluateAsync(GuardrailContext ctx, CancellationToken ct = default)
    {
        var found = ctx.Text.Split(' ').Any(w => _blocked.Contains(w));
        return ValueTask.FromResult(found
            ? GuardrailResult.Blocked("Prohibited language detected.")
            : GuardrailResult.Passed());
    }
}
```

Register in a pipeline:

```csharp
var policy = new GuardrailPolicyBuilder()
    .AddRule(new ProfanityFilter(["word1"]))
    .Build();
```

Or use a delegate for simple checks:

```csharp
.AddRule("no-tables", GuardrailPhase.Output,
    (ctx, ct) => ValueTask.FromResult(ctx.Text.Contains("|---|")
        ? GuardrailResult.Blocked("Markdown tables not allowed.")
        : GuardrailResult.Passed()))
```

## Execution order

Rules run in ascending `Order` within a phase. `IGuardrailRule.Order` defaults to 100, which places a custom rule after every built-in rule (they use orders 5 to 76 - see the [Rule Reference](rules-reference.md)). Override it to run earlier, for example before the LLM judges:

```csharp
public int Order => 30;
```

The delegate form takes the order as its last argument: `.AddRule("no-tables", GuardrailPhase.Output, evaluate, order: 30)`.

## Results

| Result | Effect |
|--------|--------|
| `GuardrailResult.Passed()` | The text continues to the next rule |
| `GuardrailResult.Blocked(reason, severity)` | Stops the pipeline; the `IChatClient` and MAF adapters reply with the policy's violation message (`OnViolation`). `severity` defaults to `GuardrailSeverity.High` |
| `GuardrailResult.Modified(newText, reason)` | Later rules, and the caller, see `newText` |
| `GuardrailResult.Error(Name, behavior, detail)` | The rule could not reach a verdict - see below |

`GuardrailResult` is a record, so rule-specific detail goes into `Metadata` with a `with` expression:

```csharp
var match = ctx.Text.Split(' ').FirstOrDefault(w => _blocked.Contains(w));
return ValueTask.FromResult(match is null
    ? GuardrailResult.Passed()
    : GuardrailResult.Blocked("Prohibited language detected.", GuardrailSeverity.Medium) with
    {
        Metadata = new Dictionary<string, object> { ["word"] = match }
    });
```

The pipeline sets `RuleName` itself. The severity is reported on the rule's span and on the `agentguard.rule.blocks` metric.

## Rules that call other services

The pipeline does not catch exceptions thrown by a rule, so a rule that calls out of process (an HTTP API, a model server) should catch its own failures and return `GuardrailResult.Error(Name, behavior, detail)`. `ErrorBehavior.FailOpen` and `ErrorBehavior.Warn` let the text through; `ErrorBehavior.FailClosed` blocks it. Every error result has `IsError = true` and `error` in `Metadata` (plus `errorDetail` when a detail is given), so callers can tell "checked and clean" from "failed to check". Let cancellation of the caller's token propagate rather than turning it into an error result:

```csharp
try
{
    var flagged = await _client.IsFlaggedAsync(context.Text, cancellationToken);
    return flagged ? GuardrailResult.Blocked("Flagged by the moderation service.") : GuardrailResult.Passed();
}
catch (HttpRequestException ex)
{
    return GuardrailResult.Error(Name, ErrorBehavior.FailOpen, ex.Message);
}
```

## Streaming

In progressive streaming, a rule is evaluated on every check cycle by default (subclasses of `LlmGuardrailRule` only once the stream ends). Implement `IStreamingGuardrailRule` to choose `StreamingEvaluationMode.EveryCheck`, `FinalOnly` (expensive checks, or checks that need the whole response) or `Adaptive` (at most once every `ProgressiveStreamingOptions.AdaptiveRuleMinCharInterval` characters).

## Releasing resources

A rule that holds resources (a model session, an `HttpClient`) can implement `IDisposable`: disposing the built policy (`GuardrailPolicy`) disposes every rule that does, including rules behind a `.When()` / `.Unless()` gate.

## Gating with `.When()` / `.Unless()`

`.When(predicate)` and `.Unless(predicate)` gate the most recently added rule, custom rules included, per request (see [Dynamic rule enabling](rules-reference.md#dynamic-rule-enabling)). The gate is a `ConditionalGuardrailRule` that reports the wrapped rule's `Name`, `Phase` and `Order`, and the built-in type-based behavior (streaming mode, tool middleware wiring) still applies to the rule inside. Code of your own that looks for a rule by type should call `rule.Unwrap()` (from `AgentGuard.Core.Rules`) first, and keep evaluating the original rule so the predicate still applies:

```csharp
var profanityRules = policy.Rules.Where(r => r.Unwrap() is ProfanityFilter);
```
