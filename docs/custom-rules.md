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

Register: `.UseAgentGuard(g => g.AddRule(new ProfanityFilter(["word1"])))`

Or use a delegate for simple checks:

```csharp
.AddRule("no-tables", GuardrailPhase.Output,
    (ctx, ct) => ValueTask.FromResult(ctx.Text.Contains("|---|")
        ? GuardrailResult.Blocked("Markdown tables not allowed.")
        : GuardrailResult.Passed()))
```
