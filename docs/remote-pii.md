# Remote PII Detection

```bash
dotnet add package AgentGuard.RemotePii --prerelease   # generic HTTP detector
dotnet add package AgentGuard.Azure --prerelease        # Azure AI Language detector
```

> **PRIVACY - READ THIS FIRST.** Both of the detectors on this page send the **raw, unredacted**
> text you're analyzing to an external process - a generic HTTP endpoint you control, or Azure AI
> Language. This inverts AgentGuard's default offline posture (`AgentGuard.Pii` / `RedactPii()` never
> leaves the process). Only use remote PII detection when you've accepted that tradeoff, and prefer
> a network boundary you control (a sidecar in the same pod/VPC) over a public internet hop where
> possible. Azure's client defaults `loggingOptOut: true` so Azure itself doesn't retain the text,
> but the text still crosses the wire to get there.

## Why remote at all?

`AgentGuard.Pii`'s regex/checksum recognizers are always-on and fully offline, but they can't detect
free-form entities like names or full addresses - that needs a model (GLiNER, ~580 MB, via
`AgentGuard.Onnx`'s `RedactPiiWithNer()`). If your process runs in a constrained container (the
motivating case: 0.5 vCPU / 500 MB, where the 22 MB Defender injection model fits fine but GLiNER
doesn't), move name/address detection **out of process** instead of skipping it. Two ways to do that:

1. **Generic remote** (`AgentGuard.RemotePii`) - point at any service that implements a small JSON
   contract. The motivating shape is a sidecar running TasmanianDevil + GLiNER in its own container,
   but the contract is generic - point it at anything that returns entity spans.
2. **Azure AI Language** (`AgentGuard.Azure`) - Azure's PII entity recognition API, which natively
   detects `Person` and full street `Address` (things GLiNER only partially covers).

Both are **detectors, not redactors**: they return entity spans (type/offset/length/score), and those
spans flow through the same local `AnonymizerEngine` as the regex/checksum entities from
`AgentGuard.Pii`. Anonymization - including reversible encrypt/decrypt, structured JSON/CSV redaction,
and conflict resolution against other entities - always happens locally. A remote/Azure outage means
you lose name/address detection for that request, not the ability to redact at all (see
[Fail-open](#fail-open-behavior) below).

## Generic remote detector

### Basic setup

```csharp
using AgentGuard.RemotePii;
using TasmanianDevil;          // PiiEntities
using TasmanianDevil.Remote;   // RemotePiiOptions

var policy = new GuardrailPolicyBuilder("safe-agent")
    .RedactPiiWithRemote(new RemotePiiOptions
    {
        Endpoint = "https://pii-sidecar.internal:8443/detect",
        SupportedEntities = [PiiEntities.Person, PiiEntities.Address],
        AuthHeaderName = "X-Api-Key",
        AuthHeaderValue = apiKey,
    })
    .Build();
```

Or the shorthand for the common case (no auth, defaults everywhere):

```csharp
var policy = new GuardrailPolicyBuilder("safe-agent")
    .RedactPiiWithRemote("https://pii-sidecar.internal:8443/detect", [PiiEntities.Person])
    .Build();
```

Both add an order-20 `PiiRule` alongside `RedactPii()` - typically you use `RedactPiiWithRemote()`
*instead of* `RedactPii()` for entities the remote side handles, since `RedactPiiWithRemote()` already
includes the full generic/US regex+checksum recognizer set (plus any country packs in the optional
`PiiOptions`) and the remote one in a single pass. The remote and Azure builders take no
`PiiRuleOptions`, so the rule they add runs on both input and output.

### The wire contract

Any server that implements this contract works. Offsets are **UTF-16 code units** - i.e. plain .NET
`string` indices, so a C# server needs no conversion and a non-.NET server needs to count UTF-16 code
units (not bytes, not Unicode codepoints) when a string contains characters outside the Basic
Multilingual Plane (emoji, some CJK extensions).

```
POST {endpoint}
Content-Type: application/json

{
  "text": "Hi, this is John Smith, call me at 555-0100.",
  "language": "en",
  "entities": ["PERSON", "ADDRESS"]
}
```

```json
{
  "entities": [
    { "type": "PERSON", "start": 12, "end": 22, "score": 0.97 }
  ]
}
```

- `entities` in the request is the set `RemotePiiOptions.SupportedEntities` intersected with whatever
  the current `PiiRule` evaluation requested - only ask the remote side for what you actually need.
- `type` in the response should match your canonical vocabulary (`PiiEntities.Person`, etc.); use
  `RemotePiiOptions.CategoryMap` if your server uses different names.
- An entity whose type (after `CategoryMap`) was not requested, or whose offsets fall outside the
  analyzed text, is dropped rather than trusted, and scores are clamped to 0-1 -
  `AgentGuard`/`TasmanianDevil` don't post-filter recognizer output, so this guard lives in the
  recognizer itself.
- Optional: set `RemotePiiOptions.RequestRedactedTextPassthrough = true` to also send
  `"includeRedactedText": true` and receive back an optional `"redactedText"` field. The field is
  parsed but neither exposed nor used for redaction (detection stays remote, redaction stays local) -
  it exists purely as a forward-looking hook.

### A sidecar recipe (TasmanianDevil + GLiNER)

The motivating sidecar is a tiny ASP.NET Minimal API in the same pod/VPC, wrapping TasmanianDevil's
own GLiNER NER recognizer so the heavy model lives in its own container:

```csharp
using TasmanianDevil.Analyzer;
using TasmanianDevil.Onnx;

var registry = new RecognizerRegistry([
    new GlinerNerRecognizer(new GlinerNerOptions
    {
        ModelPath = "/models/gliner/model_fp16.onnx",
        TokenizerPath = "/models/gliner/spm.model",
        ConfigPath = "/models/gliner/config.json",
    })
]);
var analyzer = new AnalyzerEngine(registry, defaultScoreThreshold: 0);

var app = WebApplication.Create();
app.MapPost("/detect", (DetectRequest req) =>
{
    var results = analyzer.Analyze(req.Text, req.Language, req.Entities);
    return new { entities = results.Select(r => new { type = r.EntityType, start = r.Start, end = r.End, score = r.Score }) };
});
app.Run();

record DetectRequest(string Text, string Language, string[] Entities);
```

`samples/RemotePii` in this repo demonstrates the same idea in-process (no separate container) so you
can see the pattern end to end without standing up a real sidecar; it falls back to a naive regex
name-matcher when the GLiNER model isn't downloaded, so it runs out of the box.

### Timeout, fail-open, and auth

```csharp
new RemotePiiOptions
{
    Endpoint = endpoint,
    SupportedEntities = [PiiEntities.Person, PiiEntities.Address],
    Timeout = TimeSpan.FromSeconds(3),   // default 10 s; enforced independently of the caller's own cancellation
    FailOpen = true,                     // default: swallow remote failures, keep local-only redaction
    AuthHeaderName = "Authorization",
    AuthHeaderValue = $"Bearer {token}",
}
```

Set `FailOpen = false` if losing name/address detection for a request is worse than blocking it - in
that mode a remote failure propagates out of `PiiRule.EvaluateAsync` instead of being swallowed.

## Azure AI Language detector

### Basic setup (subscription key)

```csharp
using AgentGuard.Azure.Pii;
using TasmanianDevil;

var policy = new GuardrailPolicyBuilder("safe-agent")
    .RedactPiiWithAzure(endpoint, subscriptionKey, [PiiEntities.Person, PiiEntities.Address])
    .Build();
```

### Managed identity (Azure AD)

```csharp
using Azure.Identity;

var policy = new GuardrailPolicyBuilder("safe-agent")
    .RedactPiiWithAzure(endpoint, new DefaultAzureCredential(), [PiiEntities.Person, PiiEntities.Address])
    .Build();
```

`TasmanianDevil.Azure` itself has **no** dependency on `Azure.Identity` - it takes a dependency-free
`Func<CancellationToken, ValueTask<string>>` token delegate. `AgentGuard.Azure` is the only place that
delegate gets bound to a concrete `TokenCredential`.

### Full configuration

```csharp
using TasmanianDevil.Azure;   // AzurePiiOptions, AzurePiiDomain

var policy = new GuardrailPolicyBuilder("safe-agent")
    .RedactPiiWithAzure(new AzurePiiOptions
    {
        Endpoint = endpoint,
        SubscriptionKey = subscriptionKey,        // or TokenProvider for AAD
        SupportedEntities = [PiiEntities.Person, PiiEntities.Address],
        Domain = AzurePiiDomain.Phi,               // broader clinical categories; default None
        ConfidenceThreshold = 0.7,                  // client-side post-filter
        FailOpen = true,                            // default
        Timeout = TimeSpan.FromSeconds(5),          // default 10 s
    })
    .Build();
```

Category mapping (Azure category -> canonical entity type) is built in and overridable via
`AzurePiiOptions.CategoryMap`:

| Azure category | Canonical |
|---|---|
| Person | PERSON |
| Address | ADDRESS |
| PhoneNumber | PHONE_NUMBER |
| Email | EMAIL_ADDRESS |
| Organization | ORGANIZATION |
| DateTime | DATE_TIME |
| CreditCardNumber | CREDIT_CARD |
| USSocialSecurityNumber | US_SSN |
| IPAddress | IP_ADDRESS |
| IBAN | IBAN_CODE |
| URL | URL |

### Correctness notes

- The client always sends `stringIndexType: "Utf16CodeUnit"` on the wire request - not configurable.
  Azure's service default (`TextElements_v8`) misaligns offsets against .NET strings once the text
  contains a surrogate pair (emoji, some CJK), which would silently corrupt redaction spans.
- `loggingOptOut` defaults to `true` - a PII detector should not let Azure retain the analyzed text.
- Targets the GA REST API version `2024-11-01` by default (`AzurePiiOptions.ApiVersion`).
- The synchronous API accepts at most 5,120 characters per document. With `RedactPiiWithAzure()`,
  longer text is analyzed in windows of up to 5,000 characters (500 overlap, split at whitespace where
  possible), one call at a time, and the spans are mapped back onto the full text with duplicates from
  the overlaps removed. Each window is its own call with its own timeout and fail-open handling, so an
  unresponsive endpoint can cost up to one timeout per window.

## Fail-open behavior (both detectors)

Both `RemotePiiRecognizer` and `AzurePiiRecognizer` fail open by default (`FailOpen = true`): a remote
exception, non-success response, or timeout is caught, optionally reported via `OnError`, and yields no
results for that request - **not** a thrown exception. For Azure, an error the service reports for the
document inside an otherwise successful response counts as a failure too. Local recognizers
(regex/checksum, and GLiNER if configured) still run and still redact what they can. Cancellation of
the caller's own token always propagates regardless of `FailOpen`, so it isn't mistaken for a remote
failure. Set `FailOpen = false` if partial detection is unacceptable for your use case.

## Hosting / configuration binding

Both detectors can be configured from `appsettings.json`. The `RemotePii` and `AzurePii` rule types
ship as `IGuardrailRuleFactory` implementations in their own packages (so `AgentGuard.Hosting` doesn't
pull in the Azure SDK); register the ones you use before `AddAgentGuard` (see
[configuration](configuration.md)):

```csharp
builder.Services.AddSingleton<IGuardrailRuleFactory, RemotePiiRuleFactory>();   // AgentGuard.RemotePii
builder.Services.AddSingleton<IGuardrailRuleFactory, AzurePiiRuleFactory>();    // AgentGuard.Azure
builder.Services.AddAgentGuard(builder.Configuration.GetSection("AgentGuard"));
```

`Endpoint` and `Entities` are required for both; `TimeoutSeconds` defaults to 10 and `FailOpen` to
`true`:

```json
{
  "AgentGuard": {
    "DefaultPolicy": {
      "Rules": [
        {
          "Type": "RemotePii",
          "Endpoint": "https://pii-sidecar.internal:8443/detect",
          "Entities": ["PERSON", "ADDRESS"],
          "AuthHeaderName": "X-Api-Key",
          "AuthHeaderValue": "...",
          "TimeoutSeconds": 5,
          "FailOpen": true
        },
        {
          "Type": "AzurePii",
          "Endpoint": "https://my-resource.cognitiveservices.azure.com",
          "SubscriptionKey": "...",
          "Entities": ["PERSON", "ADDRESS"],
          "Domain": "None"
        }
      ]
    }
  }
}
```

`Domain` is `None` (default) or `Phi`. For managed identity instead of a subscription key, set
`"UseManagedIdentity": true` and omit `SubscriptionKey` - `AzurePiiRuleFactory` wires up
`DefaultAzureCredential` for you.

## See also

- [`docs/rules-reference.md`](rules-reference.md) - full built-in rule table.
- [`docs/azure-integration.md`](azure-integration.md) - the other Azure AI Content Safety integrations
  (Prompt Shields, harmful content, protected material) - a different Azure product from Azure AI
  Language used here.
- `samples/RemotePii` - runnable end-to-end demo of both detectors.
