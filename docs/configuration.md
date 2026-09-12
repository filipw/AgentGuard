# Configuration

## Code-based Configuration (Fluent API)

```csharp
builder.Services.AddAgentGuard(options =>
{
    options.DefaultPolicy(p => p.BlockPromptInjection().RedactPii().LimitOutputTokens(2000));
    options.AddPolicy("strict", p => p
        .BlockPromptInjection(Sensitivity.High)
        .RedactPii()
        .EnforceTopicBoundaryWithLlm(sp.GetRequiredService<IChatClient>(), "billing"));
});
```

### Using Named Policies

```csharp
// With MAF integration (requires AgentGuard.AgentFramework)
using AgentGuard.AgentFramework;

builder.AddAIAgent("BillingAgent", (sp, key) =>
{
    var guard = sp.GetRequiredService<IAgentGuardFactory>();
    return chatClient.AsAIAgent(name: key, instructions: "...")
        .AsBuilder().UseAgentGuard(guard.GetPolicy("strict")).Build();
});

// Or use the policy directly with a standalone pipeline
var guard = sp.GetRequiredService<IAgentGuardFactory>();
var pipeline = new GuardrailPipeline(guard.GetPolicy("strict"), logger);
```

## appsettings.json Configuration

Policies can be loaded from `IConfiguration` (e.g. appsettings.json):

```csharp
builder.Services.AddAgentGuard(builder.Configuration.GetSection("AgentGuard"));
```

### JSON Schema

```json
{
  "AgentGuard": {
    "DefaultPolicy": {
      "Rules": [
        { "Type": "InputNormalization" },
        { "Type": "PromptInjection", "Sensitivity": "High" },
        { "Type": "OnnxPromptInjection", "ModelPath": "./models/deberta-v3-prompt-injection/model.onnx", "TokenizerPath": "./models/deberta-v3-prompt-injection/spm.model" },
        { "Type": "PiiRedaction", "Entities": ["EMAIL_ADDRESS", "US_SSN"], "Replacement": "[REDACTED]", "Countries": ["uk", "de"] },
        { "Type": "LlmTopicBoundary", "AllowedTopics": ["billing", "support"] },
        { "Type": "TokenLimit", "MaxTokens": 4000, "Phase": "Input", "OverflowStrategy": "Reject" }
      ],
      "ViolationMessage": "Your request was blocked by safety controls."
    },
    "Policies": {
      "strict": {
        "Rules": [
          { "Type": "PromptInjection", "Sensitivity": "High" },
          { "Type": "PiiRedaction" },
          { "Type": "TokenLimit", "MaxTokens": 2000 }
        ]
      }
    }
  }
}
```

### Available Rule Types

| Type | Properties | Notes |
|------|-----------|-------|
| `InputNormalization` | `DecodeBase64`, `DecodeHex`, `DetectReversedText`, `NormalizeUnicode` (all bool, default true) | Decodes evasion encodings |
| `PromptInjection` | `Sensitivity` (Low/Medium/High, default Medium) | Regex-based detection |
| `OnnxPromptInjection` | `ModelPath` (string, required), `TokenizerPath` (string, required), `Threshold` (float, default 0.5) | Requires `AgentGuard.Onnx` package. Fetch the model via the Kyoto bootstrap (see `eng/MODELS.md`) |
| `PiiRedaction` | `Entities` (string[], e.g. EMAIL_ADDRESS/US_SSN/CREDIT_CARD; empty = all), `Replacement` (default [REDACTED]), `Countries` (string[] of ISO codes: uk/de/in/it/es/nl; `us` is always on, listing it is a harmless no-op; empty = generic + US only) | Offline PII redaction (`AgentGuard.Pii`); regex + checksum recognizers |
| `TokenLimit` | `MaxTokens` (int), `Phase` (Input/Output), `OverflowStrategy` (Reject/Truncate/Warn) | Token counting via ML.Tokenizers |
| `ToolCallGuardrail` | `Categories` (Default/All/SqlInjection,...) | Inspects tool call arguments for injection |
| `ToolResultGuardrail` | `Action` (Block/Sanitize), `StripUnicodeControl` (bool, default true) | Detects indirect injection in tool results |
| `ContentSafety` | `MaxAllowedSeverity` (Safe/Low/Medium), `BlocklistNames` (string[]), `HaltOnBlocklistHit` (bool) | Requires `IContentSafetyClassifier` in DI |
| `LlmPromptInjection` | `IncludeClassification` (bool), `SystemPrompt` (string) | Requires `IChatClient` in DI |
| `LlmPiiDetection` | `PiiAction` (Block/Redact), `SystemPrompt` (string) | Requires `IChatClient` in DI |
| `LlmTopicBoundary` | `AllowedTopics` (string[]), `SystemPrompt` (string) | Requires `IChatClient` in DI |

### Rules from other packages

`AgentGuard.Hosting` maps the rule types that live in the core engine itself. Anything else -
the Azure and out-of-process PII adapters, or a rule of your own - plugs in through
`IGuardrailRuleFactory`, resolved from DI. That is what keeps the Azure SDK, `Azure.Identity` and
the remote-detector dependencies out of applications that only want DI registration.

| Type | Factory | Package |
|------|---------|---------|
| `RemotePii` | `RemotePiiRuleFactory` | `AgentGuard.RemotePii` |
| `AzurePii` | `AzurePiiRuleFactory` | `AgentGuard.Azure` |

Register the ones you use before `AddAgentGuard`:

```csharp
builder.Services.AddSingleton<IGuardrailRuleFactory, AzurePiiRuleFactory>();
builder.Services.AddSingleton<IGuardrailRuleFactory, RemotePiiRuleFactory>();
builder.Services.AddAgentGuard(builder.Configuration.GetSection("AgentGuard"));
```

A configured type with no matching factory throws at startup, naming the factory to register.

The same extension point takes your own rule types:

```csharp
public sealed class MyCompanyRuleFactory : IGuardrailRuleFactory
{
    public string RuleType => "MyCompanyRule";

    public void Configure(GuardrailPolicyBuilder builder, RuleConfiguration configuration) =>
        builder.AddRule(new MyCompanyRule(configuration.Endpoint));
}
```

### LLM and Cloud Rules

Rules that require external services (`LlmPromptInjection`, `LlmPiiDetection`, `LlmTopicBoundary`, `ContentSafety`) resolve their dependencies from DI. Register the required services before calling `AddAgentGuard`:

```csharp
// Register IChatClient for LLM rules
builder.Services.AddSingleton<IChatClient>(sp =>
    new OpenAIClient(apiKey).GetChatClient("gpt-4o").AsIChatClient());

// Register IContentSafetyClassifier for ContentSafety rule
builder.Services.AddSingleton<IContentSafetyClassifier>(sp =>
    new AzureContentSafetyClassifier(new ContentSafetyClient(endpoint, credential)));

// Load policies from config - LLM rules will resolve IChatClient from DI
builder.Services.AddAgentGuard(builder.Configuration.GetSection("AgentGuard"));
```

## OpenTelemetry Integration

`AgentGuard.Hosting` includes convenience extension methods for OpenTelemetry. Add them alongside your existing OTel configuration:

```csharp
using AgentGuard.Hosting;

builder.Services.AddOpenTelemetry()
    .WithTracing(t => t
        .AddAgentGuardInstrumentation()   // registers ActivitySource "AgentGuard"
        .AddAspNetCoreInstrumentation()
        .AddOtlpExporter())
    .WithMetrics(m => m
        .AddAgentGuardInstrumentation()   // registers Meter "AgentGuard"
        .AddAspNetCoreInstrumentation()
        .AddOtlpExporter());
```

If you don't use `AgentGuard.Hosting`, register the source and meter manually:

```csharp
builder.Services.AddOpenTelemetry()
    .WithTracing(t => t.AddSource("AgentGuard"))
    .WithMetrics(m => m.AddMeter("AgentGuard"));
```

See [Observability docs](observability.md) for the full span and metric reference.
