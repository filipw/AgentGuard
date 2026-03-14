# Azure AI Content Safety Integration

```bash
dotnet add package AgentGuard.Azure --prerelease
```

```csharp
using AgentGuard.Azure.ContentSafety;
using Azure.AI.ContentSafety;

var safetyClient = new ContentSafetyClient(new Uri(endpoint), new AzureKeyCredential(key));
var classifier = new AzureContentSafetyClassifier(safetyClient);

// Pass classifier to content safety rule
var rule = new ContentSafetyRule(new ContentSafetyOptions { MaxAllowedSeverity = ContentSafetySeverity.Low }, classifier);
```

## Fail-Open Behavior

If Azure is unavailable, the classifier returns empty results — the agent continues. Override by wrapping with your own fail-closed implementation.

## Cost

Azure AI Content Safety bills per API call. Consider running local heuristics first, caching results, and tuning severity thresholds.
