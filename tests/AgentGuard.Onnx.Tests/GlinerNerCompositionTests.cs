using AgentGuard.Pii.Analyzer;
using AgentGuard.Pii.Anonymizer;
using AgentGuard.Pii.Recognizers.Generic;
using FluentAssertions;
using Xunit;

namespace AgentGuard.Onnx.Tests;

/// <summary>
/// CI-safe composition tests proving NER spans flow through the same analyzer -> anonymizer pipeline
/// as the regex/checksum entities (Goal C), without requiring the ONNX model. A stub
/// <see cref="EntityRecognizer"/> stands in for <see cref="GlinerNerRecognizer"/>, returning canned
/// PERSON / LOCATION spans; the <see cref="AnalyzerEngine"/> merges them with a real regex recognizer
/// and the <see cref="AnonymizerEngine"/> redacts them uniformly.
/// </summary>
public class GlinerNerCompositionTests
{
    private static readonly string[] PersonOnly = ["PERSON"];


    // stub recognizer that locates fixed surface forms and reports them as canned NER entities
    private sealed class StubNerRecognizer(IReadOnlyDictionary<string, string> spans, double score = 0.95)
        : EntityRecognizer(spans.Values.Distinct().ToList(), name: "StubNer", supportedLanguage: "en")
    {
        public override IReadOnlyList<RecognizerResult> Analyze(string text, IReadOnlyList<string> entities)
        {
            var requested = new HashSet<string>(entities);
            var results = new List<RecognizerResult>();
            foreach (var (surface, entityType) in spans)
            {
                if (!requested.Contains(entityType))
                    continue;
                var idx = text.IndexOf(surface, StringComparison.Ordinal);
                if (idx < 0)
                    continue;
                results.Add(new RecognizerResult(entityType, idx, idx + surface.Length, score,
                    new Dictionary<string, object> { [RecognizerResult.RecognizerNameKey] = Name }));
            }

            return results;
        }
    }

    private static AnalyzerEngine BuildEngine(StubNerRecognizer ner)
    {
        var registry = new RecognizerRegistry([new EmailRecognizer(supportedLanguage: "en")]);
        registry.AddRecognizer(ner);
        return new AnalyzerEngine(registry, defaultScoreThreshold: 0);
    }

    [Fact]
    public void ShouldRedactNerAndRegexEntitiesTogetherInOnePass()
    {
        const string text = "Email jane@acme.com to reach Jane Doe in Berlin.";
        var ner = new StubNerRecognizer(new Dictionary<string, string>
        {
            ["Jane Doe"] = "PERSON",
            ["Berlin"] = "LOCATION",
        });
        var engine = BuildEngine(ner);

        var results = engine.Analyze(text, scoreThreshold: 0.4);
        var anonymized = new AnonymizerEngine().Anonymize(text, results);

        var detected = results.Select(r => r.EntityType).ToList();
        detected.Should().Contain("PERSON").And.Contain("LOCATION").And.Contain("EMAIL_ADDRESS");
        anonymized.Text.Should().Contain("<PERSON>");
        anonymized.Text.Should().Contain("<LOCATION>");
        anonymized.Text.Should().Contain("<EMAIL_ADDRESS>");
        anonymized.Text.Should().NotContain("Jane Doe");
        anonymized.Text.Should().NotContain("jane@acme.com");
    }

    [Fact]
    public void ShouldResolveOverlap_KeepingHigherScoringSpan()
    {
        // NER PERSON "Jane Doe" (0.95) vs a weaker NER ORGANIZATION over the same span (0.50);
        // overlap resolution must keep only one, and the e-mail must survive untouched.
        const string text = "Contact Jane Doe at jane@acme.com today.";
        var registry = new RecognizerRegistry([new EmailRecognizer(supportedLanguage: "en")]);
        registry.AddRecognizer(new StubNerRecognizer(new Dictionary<string, string> { ["Jane Doe"] = "PERSON" }, score: 0.95));
        registry.AddRecognizer(new StubNerRecognizer(new Dictionary<string, string> { ["Jane Doe"] = "ORGANIZATION" }, score: 0.50));
        var engine = new AnalyzerEngine(registry, defaultScoreThreshold: 0.4);

        var results = engine.Analyze(text, scoreThreshold: 0.4);
        var anonymized = new AnonymizerEngine().Anonymize(text, results);

        anonymized.Text.Should().Contain("<PERSON>");
        anonymized.Text.Should().NotContain("<ORGANIZATION>", "the lower-scoring overlapping span is dropped");
        anonymized.Text.Should().Contain("<EMAIL_ADDRESS>");
    }

    [Fact]
    public void ShouldOnlyEmitRequestedEntityTypes()
    {
        const string text = "Jane Doe lives in Berlin.";
        var ner = new StubNerRecognizer(new Dictionary<string, string>
        {
            ["Jane Doe"] = "PERSON",
            ["Berlin"] = "LOCATION",
        });
        var engine = BuildEngine(ner);

        var results = engine.Analyze(text, entities: PersonOnly, scoreThreshold: 0.4);

        results.Should().OnlyContain(r => r.EntityType == "PERSON");
    }
}
