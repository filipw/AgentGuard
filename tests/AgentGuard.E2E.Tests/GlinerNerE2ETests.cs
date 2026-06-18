using AgentGuard.Core.Abstractions;
using AgentGuard.Onnx;
using AgentGuard.Pii;
using AgentGuard.Pii.Analyzer;
using AgentGuard.Pii.Analyzer.Context;
using FluentAssertions;
using Xunit;

namespace AgentGuard.E2E.Tests;

/// <summary>
/// End-to-end tests for <see cref="GlinerNerRecognizer"/> against the real GLiNER span NER ONNX
/// export. These validate the production path (ONNX load, per-word SentencePiece assembly with
/// manual special-token ids, span enumeration, sigmoid threshold, flat-greedy decode, word->char
/// mapping) detects PERSON / LOCATION / ORGANIZATION / DATE_TIME across languages, respects the
/// threshold, and that NER spans redact in one pass with the regex entities.
///
/// Required environment variables:
///   AGENTGUARD_GLINER_ONNX_MODEL_PATH - path to the GLiNER ONNX model file
///   AGENTGUARD_GLINER_TOKENIZER_PATH  - path to the mDeBERTa-v3 spm.model
///   AGENTGUARD_GLINER_CONFIG_PATH     - path to config.json (special-token ids + max span width)
/// </summary>
public class GlinerNerE2ETests : IClassFixture<GlinerTestFixture>
{
    private readonly GlinerTestFixture _fixture;

    public GlinerNerE2ETests(GlinerTestFixture fixture) => _fixture = fixture;

    [GlinerFact]
    public void ShouldDetectAllEntityTypes_WhenEnglish()
    {
        using var recognizer = _fixture.CreateRecognizer();
        const string text = "Contact Jane Doe in Berlin at ACME Corp on March 3rd.";

        var results = recognizer.Analyze(text, recognizer.SupportedEntities);

        Surface(results, text, "PERSON").Should().Be("Jane Doe");
        Surface(results, text, "LOCATION").Should().Be("Berlin");
        Surface(results, text, "ORGANIZATION").Should().Be("ACME Corp");
        Surface(results, text, "DATE_TIME").Should().Be("March 3rd");
    }

    [GlinerFact]
    public void ShouldDetectEntities_WhenNonEnglish()
    {
        // multilingual coverage is the model's reason for existing (regex/spaCy NER are English-leaning)
        using var recognizer = _fixture.CreateRecognizer();
        const string text = "Иван Петров живёт в Москве и работает в компании Газпром.";

        var results = recognizer.Analyze(text, recognizer.SupportedEntities);

        Surface(results, text, "PERSON").Should().Be("Иван Петров");
        Surface(results, text, "LOCATION").Should().Be("Москве");
        Surface(results, text, "ORGANIZATION").Should().Be("Газпром");
    }

    [GlinerFact]
    public void ShouldDetectEntitiesInEveryChunk_WhenInputIsChunked()
    {
        // regression: when text is long enough to chunk, each chunk is decoded independently. A prior
        // bug compared chunk-LOCAL word indices across chunks, so a second entity landing at the same
        // local word position as a first was spuriously treated as overlapping and dropped. A small
        // MaxChunkChars forces ≥2 chunks; both distinct PERSONs must survive.
        using var recognizer = _fixture.CreateRecognizer(maxChunkChars: 55);
        const string text =
            "Jane Doe lives in Berlin and works there happily. Klaus Mueller lives in Munich and works there too.";

        var persons = recognizer.Analyze(text, recognizer.SupportedEntities)
            .Where(r => r.EntityType == "PERSON")
            .Select(r => text[r.Start..r.End])
            .ToList();

        persons.Should().Contain("Jane Doe");
        persons.Should().Contain("Klaus Mueller", "an entity in a later chunk must not be dropped by cross-chunk index collision");
    }

    [GlinerFact]
    public void ShouldRespectThreshold()
    {
        const string text = "Contact Jane Doe in Berlin at ACME Corp on March 3rd.";

        using var permissive = _fixture.CreateRecognizer(threshold: 0.5f);
        using var strict = _fixture.CreateRecognizer(threshold: 0.999f);

        permissive.Analyze(text, permissive.SupportedEntities).Should().NotBeEmpty();
        strict.Analyze(text, strict.SupportedEntities).Count
            .Should().BeLessThan(permissive.Analyze(text, permissive.SupportedEntities).Count,
                "a near-1.0 threshold drops all but the most confident spans");
    }

    [GlinerFact]
    public void ShouldEmitMetadata_WithModelId()
    {
        using var recognizer = _fixture.CreateRecognizer();
        const string text = "Jane Doe lives in Berlin.";

        var person = recognizer.Analyze(text, recognizer.SupportedEntities).First(r => r.EntityType == "PERSON");

        person.RecognitionMetadata.Should().NotBeNull();
        person.RecognitionMetadata!["model"].Should().Be("gliner-multi-pii-mdeberta-v3");
        person.RecognitionMetadata.Should().ContainKey("modelLabel");
        person.Score.Should().BeGreaterThan(0.5);
    }

    [GlinerFact]
    public async Task ShouldRedactNerAndRegexEntitiesInOnePass_ThroughPiiRule()
    {
        // mirrors RedactPiiWithNer: NER recognizer added to the generic+US registry, one analyzer.
        var registry = PiiRecognizers.CreateRegistry("en", countries: null);
        registry.AddRecognizer(_fixture.CreateRecognizer());
        var engine = new AnalyzerEngine(registry, new LemmaContextAwareEnhancer(), defaultScoreThreshold: 0);
        var rule = new PiiRule(new PiiOptions(), analyzer: engine);

        var ctx = new GuardrailContext
        {
            Text = "Email jane@acme.com to reach Jane Doe in Berlin.",
            Phase = GuardrailPhase.Input,
        };

        var result = await rule.EvaluateAsync(ctx);

        result.ModifiedText.Should().NotBeNull();
        result.ModifiedText.Should().Contain("<PERSON>");
        result.ModifiedText.Should().Contain("<LOCATION>");
        result.ModifiedText.Should().Contain("<EMAIL_ADDRESS>");
        result.ModifiedText.Should().NotContain("Jane Doe");
        result.ModifiedText.Should().NotContain("jane@acme.com");
    }

    private static string Surface(IReadOnlyList<RecognizerResult> results, string text, string entityType)
    {
        var r = results.Where(x => x.EntityType == entityType).OrderByDescending(x => x.Score).FirstOrDefault();
        return r is null ? string.Empty : text[r.Start..r.End];
    }
}

/// <summary>Shared fixture providing a <see cref="GlinerNerRecognizer"/> backed by real model files.</summary>
public sealed class GlinerTestFixture : IDisposable
{
    private readonly string? _modelPath;
    private readonly string? _tokenizerPath;
    private readonly string? _configPath;

    public GlinerTestFixture()
    {
        _modelPath = Environment.GetEnvironmentVariable("AGENTGUARD_GLINER_ONNX_MODEL_PATH");
        _tokenizerPath = Environment.GetEnvironmentVariable("AGENTGUARD_GLINER_TOKENIZER_PATH");
        _configPath = Environment.GetEnvironmentVariable("AGENTGUARD_GLINER_CONFIG_PATH");
    }

    public GlinerNerRecognizer CreateRecognizer(float threshold = 0.5f, int maxChunkChars = 1200)
    {
        return new GlinerNerRecognizer(new GlinerNerOptions
        {
            ModelPath = _modelPath!,
            TokenizerPath = _tokenizerPath!,
            ConfigPath = _configPath!,
            NerThreshold = threshold,
            MaxChunkChars = maxChunkChars,
        });
    }

    public void Dispose() { }
}

/// <summary>Skip fact attribute that checks for GLiNER model availability via environment variables.</summary>
[AttributeUsage(AttributeTargets.Method)]
public sealed class GlinerFactAttribute : Xunit.FactAttribute
{
    public GlinerFactAttribute()
    {
        var modelPath = Environment.GetEnvironmentVariable("AGENTGUARD_GLINER_ONNX_MODEL_PATH");
        var tokenizerPath = Environment.GetEnvironmentVariable("AGENTGUARD_GLINER_TOKENIZER_PATH");
        var configPath = Environment.GetEnvironmentVariable("AGENTGUARD_GLINER_CONFIG_PATH");

        if (string.IsNullOrEmpty(modelPath) || string.IsNullOrEmpty(tokenizerPath) || string.IsNullOrEmpty(configPath))
            Skip = "Set AGENTGUARD_GLINER_ONNX_MODEL_PATH, AGENTGUARD_GLINER_TOKENIZER_PATH, and AGENTGUARD_GLINER_CONFIG_PATH to run GLiNER NER e2e tests.";
    }
}
