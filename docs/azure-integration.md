# Azure AI Content Safety Integration

```bash
dotnet add package AgentGuard.Azure --prerelease
```

## Basic Setup

```csharp
using AgentGuard.Azure.ContentSafety;
using Azure.AI.ContentSafety;

var safetyClient = new ContentSafetyClient(new Uri(endpoint), new AzureKeyCredential(key));
var classifier = new AzureContentSafetyClassifier(safetyClient);

// Pass classifier to content safety rule
var policy = new GuardrailPolicyBuilder("safe-agent")
    .BlockHarmfulContent(classifier)
    .Build();
```

## Category Filtering

Only check specific categories instead of all four:

```csharp
var policy = new GuardrailPolicyBuilder("chat-agent")
    .BlockHarmfulContent(classifier, new ContentSafetyOptions
    {
        Categories = ContentSafetyCategory.Hate | ContentSafetyCategory.Violence,
        MaxAllowedSeverity = ContentSafetySeverity.Medium
    })
    .Build();
```

## Blocklists

Azure AI Content Safety supports server-side blocklists for custom terms (competitor names, profanity, product-specific terms). Create blocklists in the Azure portal, then reference them by name:

```csharp
var policy = new GuardrailPolicyBuilder("brand-safe")
    .BlockHarmfulContent(classifier, new ContentSafetyOptions
    {
        BlocklistNames = ["profanity-list", "competitor-names"],
        HaltOnBlocklistHit = true // skip category analysis on match (faster)
    })
    .Build();
```

Blocklist matches include metadata in the result:
- `blocklistName` — which blocklist matched
- `blocklistItemText` — the specific term that matched
- `totalMatches` — number of blocklist matches found

## Fail-Open Behavior

If Azure is unavailable, the classifier returns empty results — the agent continues. Override by wrapping with your own fail-closed implementation.

## Cost

Azure AI Content Safety bills per API call. Consider running local heuristics first, caching results, and tuning severity thresholds.
