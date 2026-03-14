# Configuration

## Dependency Injection

```csharp
builder.Services.AddAgentGuard(options =>
{
    options.DefaultPolicy(p => p.BlockPromptInjection().RedactPII().LimitOutputTokens(2000));
    options.AddPolicy("strict", p => p
        .BlockPromptInjection(Sensitivity.High)
        .RedactPII(PiiCategory.All)
        .EnforceTopicBoundary("billing"));
});
```

### Using Named Policies

```csharp
builder.AddAIAgent("BillingAgent", (sp, key) =>
{
    var guard = sp.GetRequiredService<IAgentGuardFactory>();
    return chatClient.AsAIAgent(name: key, instructions: "...")
        .AsBuilder().UseAgentGuard(guard.GetPolicy("strict")).Build();
});
```

## appsettings.json Support

Coming in v0.2.0.
