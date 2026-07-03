// AgentGuard - Remote PII Detection Sample
//
// Demonstrates out-of-process PII detection: a detector reached over a generic HTTP-shaped
// contract (an in-proc stub here, standing in for a real sidecar wrapping TasmanianDevil + GLiNER)
// returns entity spans that merge into the same local PiiRule pipeline as the regex/checksum
// recognizers. Detection moves off-box; anonymization stays local. Part 2 shows the same pattern
// against Azure AI Language, gated on env vars.

using System.Text.RegularExpressions;
using AgentGuard.Azure.Pii;
using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Builders;
using AgentGuard.RemotePii;
using TasmanianDevil;
using TasmanianDevil.Analyzer;
using TasmanianDevil.Onnx;
using TasmanianDevil.Remote;

Console.WriteLine("AgentGuard - Remote PII Detection Demo");
Console.WriteLine(new string('=', 50));

// === Part 1: generic remote PII detection (in-proc stub implementing the wire contract) ===

Console.WriteLine("\nPart 1: generic remote detector (in-proc stub)");
Console.WriteLine(new string('-', 50));

var glinerModel = Environment.GetEnvironmentVariable("AGENTGUARD_GLINER_ONNX_MODEL_PATH");
var glinerTokenizer = Environment.GetEnvironmentVariable("AGENTGUARD_GLINER_TOKENIZER_PATH");
var glinerConfig = Environment.GetEnvironmentVariable("AGENTGUARD_GLINER_CONFIG_PATH");

IPiiDetectionClient remoteStub;
if (glinerModel is not null && glinerTokenizer is not null && glinerConfig is not null)
{
    Console.WriteLine("Using the real GLiNER ONNX NER model as the 'remote' PERSON detector.");
    remoteStub = new GlinerBackedRemoteStub(glinerModel, glinerTokenizer, glinerConfig);
}
else
{
    Console.WriteLine("AGENTGUARD_GLINER_* not set - using a naive regex PERSON matcher to stand in");
    Console.WriteLine("for a real GLiNER-backed sidecar (see docs/remote-pii.md for the real setup).");
    remoteStub = new NaivePersonNameStub();
}

var remoteOptions = new RemotePiiOptions { SupportedEntities = [PiiEntities.Person] };

var remotePolicy = new GuardrailPolicyBuilder()
    .RedactPiiWithRemote(remoteStub, remoteOptions)
    .Build();
var remoteRule = remotePolicy.Rules.Single();

string[] remoteSamples =
[
    "Hi, this is John Smith. My email is john.smith@example.com and my card is 4012888888881881.",
    "Please contact Jane Doe about the invoice.",
];

foreach (var text in remoteSamples)
{
    var result = await remoteRule.EvaluateAsync(new GuardrailContext { Text = text, Phase = GuardrailPhase.Input });
    Console.WriteLine($"\n  Input:  {text}");
    Console.WriteLine(result.IsModified ? $"  Output: {result.ModifiedText}" : "  Output: (no PII detected)");
}

// === Part 2: Azure AI Language PII (gated on env) ===

Console.WriteLine("\n\nPart 2: Azure AI Language PII detector");
Console.WriteLine(new string('-', 50));

var azureEndpoint = Environment.GetEnvironmentVariable("AZURE_LANGUAGE_ENDPOINT");
var azureKey = Environment.GetEnvironmentVariable("AZURE_LANGUAGE_KEY");

if (azureEndpoint is null || azureKey is null)
{
    Console.WriteLine("Set AZURE_LANGUAGE_ENDPOINT and AZURE_LANGUAGE_KEY to run this section.");
    Console.WriteLine("Azure AI Language natively detects full street addresses, which neither the");
    Console.WriteLine("offline regex recognizers nor GLiNER can (see PiiEntities.Address).");
}
else
{
    var azurePolicy = new GuardrailPolicyBuilder()
        .RedactPiiWithAzure(azureEndpoint, azureKey, [PiiEntities.Person, PiiEntities.Address])
        .Build();
    var azureRule = azurePolicy.Rules.Single();

    const string text = "Please ship to John Smith, 221B Baker Street, London.";
    var azureResult = await azureRule.EvaluateAsync(new GuardrailContext { Text = text, Phase = GuardrailPhase.Input });
    Console.WriteLine($"\n  Input:  {text}");
    Console.WriteLine(azureResult.IsModified ? $"  Output: {azureResult.ModifiedText}" : "  Output: (no PII detected)");
}

Console.WriteLine("\nDone. See docs/remote-pii.md for the wire contract and privacy notes.");

// a naive stand-in "remote" detector so the sample runs with no downloads: matches two consecutive
// capitalized words as a PERSON span. Not production detection logic - just demo plumbing.
sealed class NaivePersonNameStub : IPiiDetectionClient
{
    private static readonly Regex TwoCapitalizedWords = new(@"\b[A-Z][a-z]+\s[A-Z][a-z]+\b", RegexOptions.Compiled);

    public ValueTask<IReadOnlyList<RemotePiiEntity>> DetectAsync(
        string text, string language, IReadOnlyList<string> entities, CancellationToken ct = default)
    {
        IReadOnlyList<RemotePiiEntity> results = TwoCapitalizedWords.Matches(text)
            .Select(m => new RemotePiiEntity(PiiEntities.Person, m.Index, m.Index + m.Length, 0.6))
            .ToList();
        return new ValueTask<IReadOnlyList<RemotePiiEntity>>(results);
    }
}

// stands in for the real sidecar: wraps TasmanianDevil's GLiNER NER recognizer directly in-process
// and adapts its results to the wire contract, so the pattern is identical to a real HTTP sidecar
// that does the same thing behind an endpoint.
sealed class GlinerBackedRemoteStub : IPiiDetectionClient
{
    private readonly AnalyzerEngine _engine;

    public GlinerBackedRemoteStub(string modelPath, string tokenizerPath, string configPath)
    {
        var nerOptions = new GlinerNerOptions { ModelPath = modelPath, TokenizerPath = tokenizerPath, ConfigPath = configPath };
        var registry = new RecognizerRegistry([new GlinerNerRecognizer(nerOptions)]);
        _engine = new AnalyzerEngine(registry, defaultScoreThreshold: 0);
    }

    public ValueTask<IReadOnlyList<RemotePiiEntity>> DetectAsync(
        string text, string language, IReadOnlyList<string> entities, CancellationToken ct = default)
    {
        IReadOnlyList<RemotePiiEntity> results = _engine.Analyze(text, language, entities)
            .Select(r => new RemotePiiEntity(r.EntityType, r.Start, r.End, r.Score))
            .ToList();
        return new ValueTask<IReadOnlyList<RemotePiiEntity>>(results);
    }
}
