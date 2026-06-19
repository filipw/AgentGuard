using FluentAssertions;
using Xunit;
using Word = AgentGuard.Onnx.GlinerModelSession.Word;
using SpanCandidate = AgentGuard.Onnx.GlinerModelSession.SpanCandidate;

namespace AgentGuard.Onnx.Tests;

/// <summary>
/// CI-safe unit tests for the GLiNER span decode logic (<see cref="GlinerModelSession"/>), driven by
/// hand-built synthetic logits - no ONNX model required. These pin the sigmoid threshold, span
/// validity, word-span to char-offset mapping, and the flat-greedy non-overlap selection that the
/// production <c>Predict</c> path relies on.
/// </summary>
public class GlinerSpanDecoderTests
{
    private const int MaxWidth = 2;

    // three words: "Alice" [0,5), "Smith" [6,11), "London" [12,18)
    private static IReadOnlyList<Word> ThreeWords() =>
    [
        new Word(0, 5, [1]),
        new Word(6, 11, [2]),
        new Word(12, 18, [3]),
    ];

    // logits flat layout [L, K, C], index = (start * maxWidth + width) * numClasses + class
    private static float[] BuildLogits(int numWords, int maxWidth, int numClasses, params (int Start, int Width, int Class, float Logit)[] hot)
    {
        var logits = new float[numWords * maxWidth * numClasses];
        Array.Fill(logits, -10f); // sigmoid(-10) ~ 0
        foreach (var (start, width, cls, logit) in hot)
            logits[(start * maxWidth + width) * numClasses + cls] = logit;
        return logits;
    }

    [Fact]
    public void ShouldEmitSpanAboveThreshold_AndMapWordSpanToCharOffsets()
    {
        var words = ThreeWords();
        var labels = new[] { "person", "location" };
        // person over words 0..1 ("Alice Smith"), location over word 2 ("London")
        var logits = BuildLogits(3, MaxWidth, 2, (0, 1, 0, 10f), (2, 0, 1, 10f));

        var sink = new List<SpanCandidate>();
        GlinerModelSession.EnumerateCandidates(logits, words, labels, numWords: 3, MaxWidth, numClasses: 2, threshold: 0.5f, sink);

        sink.Should().HaveCount(2);
        var person = sink.Single(c => c.Label == "person");
        person.WordStart.Should().Be(0);
        person.WordEnd.Should().Be(1);
        person.CharStart.Should().Be(0);   // start of "Alice"
        person.CharEnd.Should().Be(11);    // exclusive end of "Smith"
        person.Score.Should().BeApproximately(1.0f, 1e-3f);

        var location = sink.Single(c => c.Label == "location");
        location.CharStart.Should().Be(12);
        location.CharEnd.Should().Be(18);
    }

    [Fact]
    public void ShouldDropSpansBelowThreshold()
    {
        var words = ThreeWords();
        var labels = new[] { "person", "location" };
        // logit 0 -> sigmoid 0.5 exactly (kept at >=0.5); logit -0.5 -> ~0.38 (dropped)
        var logits = BuildLogits(3, MaxWidth, 2, (0, 0, 0, 0f), (1, 0, 1, -0.5f));

        var sink = new List<SpanCandidate>();
        GlinerModelSession.EnumerateCandidates(logits, words, labels, 3, MaxWidth, 2, 0.5f, sink);

        sink.Should().ContainSingle();
        sink[0].WordStart.Should().Be(0);
        sink[0].Label.Should().Be("person");
    }

    [Fact]
    public void ShouldSkipSpansExceedingSentenceLength()
    {
        var words = ThreeWords();
        var labels = new[] { "person" };
        // start=2, width=1 -> end=3 which is >= numWords(3): invalid, must not be emitted even if hot
        var logits = BuildLogits(3, MaxWidth, 1, (2, 1, 0, 10f));

        var sink = new List<SpanCandidate>();
        GlinerModelSession.EnumerateCandidates(logits, words, labels, 3, MaxWidth, 1, 0.5f, sink);

        sink.Should().BeEmpty("a span ending past the last word is out of range");
    }

    [Fact]
    public void ShouldDropLowerScoringOverlappingSpan_InFlatGreedyDecode()
    {
        // (0,1) person 0.99 overlaps (0,0) person 0.9 -> only the higher survives
        var candidates = new List<SpanCandidate>
        {
            new(WordStart: 0, WordEnd: 1, CharStart: 0, CharEnd: 11, Label: "person", Score: 0.99f),
            new(WordStart: 0, WordEnd: 0, CharStart: 0, CharEnd: 5, Label: "person", Score: 0.90f),
            new(WordStart: 2, WordEnd: 2, CharStart: 12, CharEnd: 18, Label: "location", Score: 0.80f),
        };

        var selected = GlinerModelSession.GreedyFlatDecode(candidates);

        selected.Should().HaveCount(2);
        selected.Should().ContainSingle(c => c.Label == "person").Which.WordEnd.Should().Be(1);
        selected.Should().ContainSingle(c => c.Label == "location");
    }

    [Fact]
    public void ShouldReturnSpansSortedByStartWord()
    {
        var candidates = new List<SpanCandidate>
        {
            new(2, 2, 12, 18, "location", 0.80f),
            new(0, 0, 0, 5, "person", 0.95f),
        };

        var selected = GlinerModelSession.GreedyFlatDecode(candidates);

        selected.Should().HaveCount(2);
        selected[0].WordStart.Should().Be(0);
        selected[1].WordStart.Should().Be(2);
    }

    [Fact]
    public void ShouldKeepAdjacentNonOverlappingSpans()
    {
        // (0,0) and (1,1) are adjacent but disjoint word ranges -> both kept
        var candidates = new List<SpanCandidate>
        {
            new(0, 0, 0, 5, "person", 0.9f),
            new(1, 1, 6, 11, "person", 0.85f),
        };

        var selected = GlinerModelSession.GreedyFlatDecode(candidates);

        selected.Should().HaveCount(2);
    }

    [Fact]
    public void ShouldTreatEqualWordRangeWithDifferentLabelsAsOverlap()
    {
        // same (start,end) span scored under two labels -> flat NER keeps only the higher-scoring one
        var candidates = new List<SpanCandidate>
        {
            new(0, 1, 0, 11, "organization", 0.70f),
            new(0, 1, 0, 11, "person", 0.92f),
        };

        var selected = GlinerModelSession.GreedyFlatDecode(candidates);

        selected.Should().ContainSingle();
        selected[0].Label.Should().Be("person");
    }
}
