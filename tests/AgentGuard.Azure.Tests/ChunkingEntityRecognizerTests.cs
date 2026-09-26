using System.Text;
using AgentGuard.Azure.Pii;
using FluentAssertions;
using TasmanianDevil.Analyzer;
using Xunit;

namespace AgentGuard.Azure.Tests;

public class ChunkingEntityRecognizerTests
{
    private const int MaxLength = 1_000;
    private const int Overlap = 100;

    private static readonly IReadOnlyList<string> Person = ["PERSON"];

    private static string Words(int length)
    {
        var words = new[] { "notes", "from", "the", "weekly", "sync", "about", "roadmap", "items" };
        var builder = new StringBuilder(length + 16);
        for (var i = 0; builder.Length < length; i++)
            builder.Append(words[i % words.Length]).Append(' ');

        return builder.ToString(0, length);
    }

    private static IEnumerable<(int Start, int End)> Spans(IEnumerable<RecognizerResult> results) =>
        results.Select(r => (r.Start, r.End));

    private static IEnumerable<(int Start, int End)> Occurrences(string text, string value)
    {
        for (var at = text.IndexOf(value, StringComparison.Ordinal); at >= 0; at = text.IndexOf(value, at + 1, StringComparison.Ordinal))
            yield return (at, at + value.Length);
    }

    [Fact]
    public void ShouldPassTheTextThrough_WhenItFitsInOneWindow()
    {
        var inner = new NameRecognizer(MaxLength);
        var recognizer = new ChunkingEntityRecognizer(inner, MaxLength, Overlap);
        const string text = "call John Smith";

        var results = recognizer.Analyze(text, Person);

        inner.Inputs.Should().ContainSingle().Which.Should().BeSameAs(text);
        Spans(results).Should().Equal((5, 15));
    }

    [Fact]
    public void ShouldKeepEveryCallWithinTheLimitAndMapSpansBack_WhenTextIsLong()
    {
        var inner = new NameRecognizer(MaxLength);
        var recognizer = new ChunkingEntityRecognizer(inner, MaxLength, Overlap);
        var text = "John Smith " + Words(1_500) + " John Smith " + Words(1_500) + " John Smith";

        var results = recognizer.Analyze(text, Person);

        inner.Inputs.Should().HaveCountGreaterThan(1).And.OnlyContain(i => i.Length <= MaxLength);
        Spans(results).Should().BeEquivalentTo(Occurrences(text, "John Smith"));
        results.Select(r => text.Substring(r.Start, r.End - r.Start)).Should().OnlyContain(name => name == "John Smith");
    }

    [Fact]
    public async Task ShouldKeepEveryCallWithinTheLimitAndMapSpansBack_WhenAnalyzingAsync()
    {
        var inner = new NameRecognizer(MaxLength, requiresAsync: true);
        var recognizer = new ChunkingEntityRecognizer(inner, MaxLength, Overlap);
        var text = Words(2_500) + " John Smith " + Words(2_500);

        var results = await recognizer.AnalyzeAsync(text, Person);

        inner.Inputs.Should().HaveCountGreaterThan(1).And.OnlyContain(i => i.Length <= MaxLength);
        Spans(results).Should().BeEquivalentTo(Occurrences(text, "John Smith"));
    }

    [Fact]
    public void ShouldReportASpanOnce_WhenTwoOverlappingWindowsBothSeeIt()
    {
        var inner = new NameRecognizer(MaxLength);
        var recognizer = new ChunkingEntityRecognizer(inner, MaxLength, Overlap);
        var text = Words(930) + " John Smith " + Words(1_000);

        var results = recognizer.Analyze(text, Person);

        inner.Inputs.Count(i => i.Contains("John Smith", StringComparison.Ordinal)).Should().Be(2);
        Spans(results).Should().Equal(Occurrences(text, "John Smith"));
    }

    [Fact]
    public void ShouldPreferTheWholeSpan_WhenAWindowBoundaryCutThroughIt()
    {
        // the first window ends between "John" and "Smith", and the recognizer reports the "John"
        // it saw there; the next window sees the whole name, which supersedes the fragment
        var inner = new NameRecognizer(MaxLength);
        var recognizer = new ChunkingEntityRecognizer(inner, MaxLength, Overlap);
        var text = new string('x', 989) + " John Smith " + new string('x', 500);

        var results = recognizer.Analyze(text, Person);

        inner.Inputs[0].Should().EndWith("John ");
        Spans(results).Should().Equal((990, 1_000));
    }

    [Fact]
    public void ShouldNotAnalyzeWhitespaceOnlyWindows_WhenTextIsMostlyWhitespace()
    {
        var inner = new NameRecognizer(MaxLength);
        var recognizer = new ChunkingEntityRecognizer(inner, MaxLength, Overlap);
        var text = "John Smith" + new string(' ', 5_000) + "John Smith";

        var results = recognizer.Analyze(text, Person);

        inner.Inputs.Should().HaveCount(2);
        Spans(results).Should().BeEquivalentTo(Occurrences(text, "John Smith"));
    }

    [Fact]
    public void ShouldTakeOnTheInnerRecognizersIdentity_WhenWrapping()
    {
        var inner = new NameRecognizer(MaxLength, requiresAsync: true, language: "de");

        var recognizer = new ChunkingEntityRecognizer(inner, MaxLength, Overlap);

        recognizer.SupportedEntities.Should().Equal(inner.SupportedEntities);
        recognizer.SupportedLanguage.Should().Be("de");
        recognizer.Name.Should().Be(inner.Name);
        recognizer.Context.Should().Equal("name", "called");
        recognizer.RequiresAsync.Should().BeTrue();
    }

    [Fact]
    public async Task ShouldPropagateCancellation_WhenTheCallerCancels()
    {
        var recognizer = new ChunkingEntityRecognizer(new NameRecognizer(MaxLength, requiresAsync: true), MaxLength, Overlap);
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        var act = async () => await recognizer.AnalyzeAsync(Words(5_000), Person, cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    [Theory]
    [InlineData(500)]
    [InlineData(5_000)]
    public async Task ShouldPropagateCancellation_WhenAFailOpenInnerRecognizerAnswersACanceledRequestWithNothing(int length)
    {
        // a fail-open recognizer can turn the failure of a request the caller's cancellation tore down
        // into an empty answer; the chunker must not hand that back as the result
        using var cts = new CancellationTokenSource();
        var recognizer = new ChunkingEntityRecognizer(new CancelingFailOpenRecognizer(cts), MaxLength, Overlap);

        var act = async () => await recognizer.AnalyzeAsync("John Smith " + Words(length), Person, cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    [Fact]
    public void ShouldThrow_WhenTheWindowSettingsCannotMakeProgress()
    {
        var act = () => new ChunkingEntityRecognizer(new NameRecognizer(MaxLength), maxChunkLength: 100, chunkOverlap: 60);

        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    /// <summary>
    /// Cancels the caller on its first call and answers with no entities, like a fail-open detector
    /// whose request failed as the cancellation tore it down.
    /// </summary>
    private sealed class CancelingFailOpenRecognizer(CancellationTokenSource caller)
        : EntityRecognizer(["PERSON"], supportedLanguage: "en")
    {
        public override bool RequiresAsync => true;

        public override IReadOnlyList<RecognizerResult> Analyze(string text, IReadOnlyList<string> entities) => [];

        public override async ValueTask<IReadOnlyList<RecognizerResult>> AnalyzeAsync(
            string text, IReadOnlyList<string> entities, CancellationToken ct = default)
        {
            await caller.CancelAsync();
            return [];
        }
    }

    /// <summary>
    /// Reports every "John Smith" as a PERSON, plus a trailing "John" as a fragment - what a detector
    /// does when a window boundary cuts a name in half. Refuses input over its limit, like the service.
    /// </summary>
    private sealed class NameRecognizer(int maxLength, bool requiresAsync = false, string language = "en")
        : EntityRecognizer(["PERSON"], supportedLanguage: language, context: ["name", "called"])
    {
        public List<string> Inputs { get; } = [];

        public override bool RequiresAsync => requiresAsync;

        public override IReadOnlyList<RecognizerResult> Analyze(string text, IReadOnlyList<string> entities)
        {
            Inputs.Add(text);
            if (text.Length > maxLength)
                throw new InvalidOperationException($"input of {text.Length} characters is over the limit");

            var results = Occurrences(text, "John Smith")
                .Select(s => new RecognizerResult("PERSON", s.Start, s.End, 0.9))
                .ToList();

            var trimmed = text.TrimEnd();
            if (trimmed.EndsWith(" John", StringComparison.Ordinal))
                results.Add(new RecognizerResult("PERSON", trimmed.Length - 4, trimmed.Length, 0.95));

            return results;
        }

        public override async ValueTask<IReadOnlyList<RecognizerResult>> AnalyzeAsync(
            string text, IReadOnlyList<string> entities, CancellationToken ct = default)
        {
            await Task.Yield();
            ct.ThrowIfCancellationRequested();
            return Analyze(text, entities);
        }
    }
}
