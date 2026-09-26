# Configuration

## Code-based Configuration (Fluent API)

```csharp
// the client the LLM rules call
IChatClient judge = new OpenAIClient(apiKey).GetChatClient("gpt-4o").AsIChatClient();

builder.Services.AddAgentGuard(options =>
{
    options.DefaultPolicy(p => p.BlockPromptInjection().RedactPii().LimitOutputTokens(2000));
    options.AddPolicy("strict", p => p
        .BlockPromptInjection(Sensitivity.High)
        .RedactPii()
        .EnforceTopicBoundaryWithLlm(judge, "billing"));
});
```

The policy callbacks receive the builder, not the service provider, so services a rule needs (such as the `IChatClient` above) are created or captured outside them. Policies loaded from configuration resolve those services from DI instead (see [LLM and Cloud Rules](#llm-and-cloud-rules)).

### Using Named Policies

```csharp
// With MAF integration (requires AgentGuard.AgentFramework)
using AgentGuard.AgentFramework;

builder.AddAIAgent("BillingAgent", (sp, key) =>
{
    var guard = sp.GetRequiredService<IAgentGuardFactory>();
    return chatClient.AsAIAgent(name: key, instructions: "...")
        .AsBuilder().UseAgentGuard(guard.GetPolicy("strict"))
        .Build(sp);   // building with sp lets a ledger registered with AddAgentGuard reach the middleware
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

Type names and enum values (`Sensitivity`, `Action`, ...) are matched case-insensitively. Enum settings take member names only (a comma-separated list of names for `Categories`), not numbers. An unknown type, an invalid or out-of-range value (such as a `Threshold` outside 0-1, `MaxTokens` below 1, or a `WindowOverlap` not smaller than `WindowSize`), or a missing required property throws an `InvalidOperationException` naming the rule type and setting when the policies are built - the first time `IAgentGuardFactory` or the registered `GuardrailPipeline` is resolved.

| Type | Properties | Notes |
|------|-----------|-------|
| `InputNormalization` | `DecodeBase64`, `DecodeHex`, `DetectReversedText`, `NormalizeUnicode` (all bool, default true) | Decodes evasion encodings. Leetspeak decoding and invisible-character stripping (including Unicode tag characters) keep their defaults (on) |
| `PromptInjection` | `Sensitivity` (Low/Medium/High, default Medium) | Regex-based detection |
| `DefenderPromptInjection` | `Threshold` (float 0-1, default 0.75 - the main-head threshold), `WindowSize` (tokens, default 64), `WindowOverlap` (tokens, default 32), `MaxWindows` (default 512; 0 = no limit) | Bundled Defender model (`AgentGuard.Onnx`); no download. The aux veto and temperature keep their calibrated defaults. Long input is classified in overlapping windows; input needing more than `MaxWindows` windows is blocked |
| `DebertaPromptInjection` | `ModelPath` (string, required), `TokenizerPath` (string, required), `Threshold` (float 0-1, default 0.5), `WindowSize` (tokens, default 510), `WindowOverlap` (tokens, default 128), `MaxWindows` (default 32; 0 = no limit) | Bring-your-own DeBERTa v3 model (`AgentGuard.Onnx`). Fetch the model via the Kyoto bootstrap (see `eng/MODELS.md`) |
| `OnnxPromptInjection` | With `ModelPath`: as `DebertaPromptInjection`. Without: as `DefenderPromptInjection` | Uses the bundled Defender model unless `ModelPath` is set |
| `PiiRedaction` | `Entities` (string[], e.g. EMAIL_ADDRESS/US_SSN/CREDIT_CARD; empty = all), `Replacement` (default `<ENTITY_TYPE>` tags; set e.g. `[REDACTED]` for one flat replacement), `Countries` (string[] of ISO codes: uk/de/in/it/es/nl; `us` is always on, listing it is a harmless no-op; empty = generic + US only) | Offline PII redaction (`AgentGuard.Pii`); regex + checksum recognizers |
| `Secrets` | `SecretAction` (Block/Redact, default Block) | API keys, tokens, private keys, connection strings |
| `Retrieval` | `DetectPromptInjection` (bool, default true), `DetectSecrets` (bool, default true), `DetectPii` (bool, default false), `RetrievalAction` (Remove/Sanitize, default Remove) | Filters retrieved chunks passed in `GuardrailContext.Properties["RetrievalChunks"]` |
| `TokenLimit` | `MaxTokens` (int, default 4000), `Phase` (Input/Output, default Input), `OverflowStrategy` (Reject/Truncate/Warn; default Reject for input, Truncate for output) | Token counting via ML.Tokenizers |
| `ToolCallGuardrail` | `Categories` (Default, All, or a comma-separated list of SqlInjection, CodeInjection, PathTraversal, CommandInjection, Ssrf, TemplateInjection, Xss; default Default) | Inspects tool call arguments for injection |
| `ToolResultGuardrail` | `Action` (Block/Sanitize, default Block - Sanitize removes each injection from the start of its line to the end of its paragraph), `StripUnicodeControl` (bool, default true; includes Unicode tag characters) | Detects indirect injection in tool results |
| `ContentSafety` | `MaxAllowedSeverity` (Safe/Low/Medium, default Low), `BlocklistNames` (string[]), `HaltOnBlocklistHit` (bool, default false) | Requires `IContentSafetyClassifier` in DI |
| `LlmPromptInjection` | `IncludeClassification` (bool, default true), `SystemPrompt` (string) | Requires `IChatClient` in DI |
| `LlmPiiDetection` | `PiiAction` (Block/Redact, default Redact), `SystemPrompt` (string) | Requires `IChatClient` in DI |
| `LlmTopicBoundary` | `AllowedTopics` (string[], required, non-empty), `SystemPrompt` (string) | Requires `IChatClient` in DI |
| `LlmOutputPolicy` | `PolicyDescription` (string, required), `OutputPolicyAction` (Block/Warn, default Block), `SystemPrompt` (string) | Requires `IChatClient` in DI |
| `LlmGroundedness` | `GroundednessAction` (Block/Warn, default Block), `SystemPrompt` (string) | Requires `IChatClient` in DI |
| `LlmCopyright` | `CopyrightAction` (Block/Warn, default Block), `SystemPrompt` (string) | Requires `IChatClient` in DI |

Some rules have no configuration type and are added in code only: `BlockPromptInjectionWithPIGuard()`, `BlockUnsafeContentWithOpir()`, `RedactPiiWithNer()`, `BlockPromptInjectionWithRemoteClassifier()`, `BlockPromptInjectionWithAzurePromptShield()`, `BlockProtectedMaterialWithAzure()`, and `ValidateInput()` / `ValidateOutput()`. The same goes for `.When()` / `.Unless()` gates, progressive streaming and re-ask. Use [code-based configuration](#code-based-configuration-fluent-api) for these, or expose one through an `IGuardrailRuleFactory` of your own (below).

### Rules from other packages

`AgentGuard.Hosting` maps the rule types above itself. Anything else - the Azure and
out-of-process PII adapters, or a rule of your own - plugs in through `IGuardrailRuleFactory`,
resolved from DI. That is what keeps the Azure SDK, `Azure.Identity` and the remote-detector
dependencies out of applications that only want DI registration.

| Type | Factory | Package | Properties |
|------|---------|---------|-----------|
| `RemotePii` | `RemotePiiRuleFactory` | `AgentGuard.RemotePii` | `Endpoint` (required), `Entities` (required), `AuthHeaderName`, `AuthHeaderValue`, `TimeoutSeconds` (at least 1, default 10), `FailOpen` (default true), `Replacement`, `Countries` |
| `AzurePii` | `AzurePiiRuleFactory` | `AgentGuard.Azure` | `Endpoint` (required), `Entities` (required), `SubscriptionKey` (required unless `UseManagedIdentity` is true), `UseManagedIdentity` (default false; uses `DefaultAzureCredential`), `Domain` (None/Phi, default None), `TimeoutSeconds` (at least 1, default 10), `FailOpen` (default true), `Replacement`, `Countries` |

Both add a PII rule that runs the offline recognizers plus the remote detector. `Entities` is the set the remote detector is asked for; `Replacement` and `Countries` work as for `PiiRedaction` (default `<ENTITY_TYPE>` tags; generic + US recognizers plus the listed country packs). See [Remote PII Detection](remote-pii.md).

Register the ones you use before `AddAgentGuard`:

```csharp
builder.Services.AddSingleton<IGuardrailRuleFactory, AzurePiiRuleFactory>();
builder.Services.AddSingleton<IGuardrailRuleFactory, RemotePiiRuleFactory>();
builder.Services.AddAgentGuard(builder.Configuration.GetSection("AgentGuard"));
```

A configured type with no matching factory throws when the policies are built, naming the factories to register.

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

Rules that require external services (`LlmPromptInjection`, `LlmPiiDetection`, `LlmTopicBoundary`, `LlmOutputPolicy`, `LlmGroundedness`, `LlmCopyright`, `ContentSafety`) resolve their dependencies from DI. Register the required services before calling `AddAgentGuard`:

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
