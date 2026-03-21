# Configuration

## Code-based Configuration (Fluent API)

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
        { "Type": "PiiRedaction", "Categories": "All", "Replacement": "[REDACTED]" },
        { "Type": "TopicBoundary", "AllowedTopics": ["billing", "support"], "SimilarityThreshold": 0.5 },
        { "Type": "TokenLimit", "MaxTokens": 4000, "Phase": "Input", "OverflowStrategy": "Reject" }
      ],
      "ViolationMessage": "Your request was blocked by safety controls."
    },
    "Policies": {
      "strict": {
        "Rules": [
          { "Type": "PromptInjection", "Sensitivity": "High" },
          { "Type": "PiiRedaction", "Categories": "All" },
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
| `OnnxPromptInjection` | `ModelPath` (string, required), `TokenizerPath` (string, required), `Threshold` (float, default 0.5) | Requires `AgentGuard.Onnx` package. Download model via `eng/download-onnx-model.sh` |
| `PiiRedaction` | `Categories` (Default/All/Email,Phone,...), `Replacement` (default [REDACTED]) | Regex-based redaction |
| `TopicBoundary` | `AllowedTopics` (string[]), `SimilarityThreshold` (float, default 0.3) | Keyword-based topic matching |
| `TokenLimit` | `MaxTokens` (int), `Phase` (Input/Output), `OverflowStrategy` (Reject/Truncate/Warn) | Token counting via ML.Tokenizers |
| `ContentSafety` | `MaxAllowedSeverity` (Safe/Low/Medium), `BlocklistNames` (string[]), `HaltOnBlocklistHit` (bool) | Requires `IContentSafetyClassifier` in DI |
| `LlmPromptInjection` | `IncludeClassification` (bool), `SystemPrompt` (string) | Requires `IChatClient` in DI |
| `LlmPiiDetection` | `PiiAction` (Block/Redact), `SystemPrompt` (string) | Requires `IChatClient` in DI |
| `LlmTopicBoundary` | `AllowedTopics` (string[]), `SystemPrompt` (string) | Requires `IChatClient` in DI |

### LLM and Cloud Rules

Rules that require external services (`LlmPromptInjection`, `LlmPiiDetection`, `LlmTopicBoundary`, `ContentSafety`) resolve their dependencies from DI. Register the required services before calling `AddAgentGuard`:

```csharp
// Register IChatClient for LLM rules
builder.Services.AddSingleton<IChatClient>(sp =>
    new OpenAIClient(apiKey).GetChatClient("gpt-4o").AsIChatClient());

// Register IContentSafetyClassifier for ContentSafety rule
builder.Services.AddSingleton<IContentSafetyClassifier>(sp =>
    new AzureContentSafetyClassifier(new ContentSafetyClient(endpoint, credential)));

// Load policies from config — LLM rules will resolve IChatClient from DI
builder.Services.AddAgentGuard(builder.Configuration.GetSection("AgentGuard"));
```
