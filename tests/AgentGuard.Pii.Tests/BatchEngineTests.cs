using AgentGuard.Pii.Analyzer;
using AgentGuard.Pii.Analyzer.Context;
using AgentGuard.Pii.Batch;
using FluentAssertions;
using Xunit;

namespace AgentGuard.Pii.Tests;

public class BatchEngineTests
{
    private readonly AnalyzerEngine _analyzer = new(
        PiiRecognizers.CreateDefaultRegistry("en"),
        new LemmaContextAwareEnhancer());

    [Fact]
    public void ShouldMatchSingleCalls_WhenAnalyzingList()
    {
        var texts = new[] { "email john@example.com", "no pii here", "card 4012888888881881" };
        var batch = new BatchAnalyzerEngine(_analyzer);

        var batched = batch.Analyze(texts, scoreThreshold: 0.4);

        batched.Should().HaveCount(3);
        for (var i = 0; i < texts.Length; i++)
        {
            var single = _analyzer.Analyze(texts[i], scoreThreshold: 0.4);
            batched[i].Select(r => (r.EntityType, r.Start, r.End))
                .Should().Equal(single.Select(r => (r.EntityType, r.Start, r.End)));
        }
    }

    [Fact]
    public void ShouldHandleEmptyAndWhitespace()
    {
        var batch = new BatchAnalyzerEngine(_analyzer);

        var results = batch.Analyze(["", "   ", "john@example.com"]);

        results[0].Should().BeEmpty();
        results[1].Should().BeEmpty();
        results[2].Should().NotBeEmpty();
    }

    [Fact]
    public void ShouldPreserveKeys_WhenAnalyzingDictionary()
    {
        var records = new Dictionary<string, string>
        {
            ["email"] = "john@example.com",
            ["note"] = "nothing here",
        };
        var batch = new BatchAnalyzerEngine(_analyzer);

        var results = batch.Analyze(records);

        results.Should().ContainKeys("email", "note");
        results["email"].Should().Contain(r => r.EntityType == "EMAIL_ADDRESS");
        results["note"].Should().BeEmpty();
    }

    [Fact]
    public void ShouldAnonymizeListInOrder()
    {
        var texts = new[] { "email john@example.com", "no pii here" };
        var analyzer = new BatchAnalyzerEngine(_analyzer);
        var anonymizer = new BatchAnonymizerEngine();

        var detections = analyzer.Analyze(texts, scoreThreshold: 0.4);
        var anonymized = anonymizer.Anonymize(texts, detections);

        anonymized[0].Text.Should().Be("email <EMAIL_ADDRESS>");
        anonymized[1].Text.Should().Be("no pii here");
    }

    [Fact]
    public void ShouldAnonymizeDictionaryPreservingKeys()
    {
        var records = new Dictionary<string, string>
        {
            ["primary"] = "john@example.com",
            ["note"] = "all clear",
        };
        var analyzer = new BatchAnalyzerEngine(_analyzer);
        var anonymizer = new BatchAnonymizerEngine();

        var detections = analyzer.Analyze(records);
        var anonymized = anonymizer.Anonymize(records, detections);

        anonymized.Should().ContainKeys("primary", "note");
        anonymized["primary"].Text.Should().Be("<EMAIL_ADDRESS>");
        anonymized["note"].Text.Should().Be("all clear");
    }

    [Fact]
    public void ShouldThrow_WhenListLengthsDiffer()
    {
        var anonymizer = new BatchAnonymizerEngine();
        var texts = new[] { "a", "b" };
        var results = new List<IReadOnlyList<RecognizerResult>> { new List<RecognizerResult>() };

        var act = () => anonymizer.Anonymize(texts, results);

        act.Should().Throw<ArgumentException>().WithMessage("*same length*");
    }
}
