using System.Globalization;
using FluentAssertions;
using Microsoft.ML.Tokenizers;
using Xunit;

namespace AgentGuard.Onnx.Tests;

/// <summary>
/// Unit tests for <see cref="TextWindowSplitter"/>. Most use simple word- and character-based token
/// counters so the windowing logic is verified in isolation; one property test runs it with the
/// Defender rule's real WordPiece tokenizer (bundled vocab only, no model is loaded).
/// </summary>
public class TextWindowSplitterTests
{
    [Fact]
    public void ShouldReturnSingleWholeTextWindow_WhenTextFitsInOneWindow()
    {
        var splitter = new TextWindowSplitter(WindowingTestHelpers.CountWords, windowSize: 8, windowOverlap: 4);
        const string text = "  one two three four five six seven eight  ";

        var windows = splitter.Split(text);

        windows.Should().Equal([new TextWindow(0, text.Length)], "text that fits must be classified whole, whitespace included");
    }

    [Fact]
    public void ShouldCoverEveryWord_WhenTextIsLongerThanOneWindow()
    {
        var splitter = new TextWindowSplitter(WindowingTestHelpers.CountWords, windowSize: 10, windowOverlap: 4);
        var text = WindowingTestHelpers.Words(103);

        var windows = splitter.Split(text);

        windows.Should().HaveCountGreaterThan(1);
        windows.Select(w => text.Substring(w.Start, w.Length)).Should().OnlyContain(
            window => WindowingTestHelpers.CountWords(window) <= 10 && window == window.Trim(),
            "every window fits and starts and ends on a word");
        windows.SelectMany(w => text.Substring(w.Start, w.Length).Split(' ')).Distinct()
            .Should().HaveCount(103, "no word may be left out");
        windows[0].Start.Should().Be(0);
        windows[^1].End.Should().Be(text.Length);
    }

    [Fact]
    public void ShouldOverlapConsecutiveWindows_WhenOverlapIsConfigured()
    {
        var splitter = new TextWindowSplitter(WindowingTestHelpers.CountWords, windowSize: 10, windowOverlap: 4);
        var text = WindowingTestHelpers.Words(100);

        var windows = splitter.Split(text).Select(w => text.Substring(w.Start, w.Length).Split(' ')).ToList();

        for (var i = 0; i + 2 < windows.Count; i++)
            windows[i].Intersect(windows[i + 1]).Should().HaveCount(4, $"windows {i} and {i + 1} share the configured overlap");
    }

    [Fact]
    public void ShouldMakeLastWindowFullSize_WhenTextEndsMidStride()
    {
        var splitter = new TextWindowSplitter(WindowingTestHelpers.CountWords, windowSize: 10, windowOverlap: 4);
        var text = WindowingTestHelpers.Words(23);

        var windows = splitter.Split(text);

        var last = text.Substring(windows[^1].Start, windows[^1].Length);
        WindowingTestHelpers.CountWords(last).Should().Be(10, "the tail is classified with a full window of context");
        last.Should().EndWith("w22");
    }

    [Theory]
    [InlineData(10, 4)]
    [InlineData(10, 5)]
    [InlineData(64, 32)]
    [InlineData(16, 0)]
    public void ShouldPlaceEveryShortSpanInsideOneWindow_WhenSpanIsNoLongerThanOverlapPlusOne(int windowSize, int windowOverlap)
    {
        var splitter = new TextWindowSplitter(WindowingTestHelpers.CountWords, windowSize, windowOverlap);
        const int wordCount = 500;
        var text = WindowingTestHelpers.Words(wordCount);
        var windows = splitter.Split(text).Select(w => WordRange(text, w)).ToList();

        var spanLength = windowOverlap + 1;
        for (var first = 0; first + spanLength <= wordCount; first++)
        {
            var last = first + spanLength - 1;
            windows.Should().Contain(range => range.First <= first && last <= range.Last,
                $"words {first}-{last} must lie entirely within one window");
        }
    }

    [Fact]
    public void ShouldCutRunWithoutWhitespace_WhenRunIsLongerThanOneWindow()
    {
        // one token per character, and a single 1000-character run with no whitespace to split at
        var splitter = new TextWindowSplitter(WindowingTestHelpers.CountNonWhitespaceChars, windowSize: 64, windowOverlap: 32);
        var text = "prefix " + new string('x', 1000) + " suffix";

        var windows = splitter.Split(text);

        windows.Select(w => WindowingTestHelpers.CountNonWhitespaceChars(text.AsSpan(w.Start, w.Length)))
            .Should().OnlyContain(tokens => tokens <= 64);
        CoveredCharacters(text, windows).Should().Be(text.Count(c => !char.IsWhiteSpace(c)), "every character must be classified");
        for (var i = 0; i + 1 < windows.Count; i++)
            windows[i + 1].Start.Should().BeLessThan(windows[i].End, "consecutive windows still overlap inside the run");
    }

    [Fact]
    public void ShouldNotCutSurrogatePairs_WhenCuttingRunWithoutWhitespace()
    {
        // each emoji is a surrogate pair counted as one token
        var splitter = new TextWindowSplitter(
            text => new StringInfo(text.ToString()).LengthInTextElements,
            windowSize: 7,
            windowOverlap: 3);
        var text = string.Concat(Enumerable.Repeat("\U0001F600", 200));

        var windows = splitter.Split(text);

        windows.Should().HaveCountGreaterThan(1);
        foreach (var window in windows)
        {
            char.IsLowSurrogate(text[window.Start]).Should().BeFalse("a window must not start inside a surrogate pair");
            char.IsHighSurrogate(text[window.End - 1]).Should().BeFalse("a window must not end inside a surrogate pair");
        }

        CoveredCharacters(text, windows).Should().Be(text.Length);
    }

    [Fact]
    public void ShouldShrinkWindows_WhenPerWordCountsUndercountTheRealCount()
    {
        // a tokenizer that also turns every run of two or more whitespace characters into a token, which
        // per-word counting cannot see; windows must still fit by the real count
        static int CountWithWhitespaceTokens(ReadOnlySpan<char> text)
        {
            var count = WindowingTestHelpers.CountWords(text);
            var run = 0;
            foreach (var c in text)
            {
                if (char.IsWhiteSpace(c))
                {
                    run++;
                    if (run == 2)
                        count++;
                }
                else
                {
                    run = 0;
                }
            }

            return count;
        }

        var splitter = new TextWindowSplitter(CountWithWhitespaceTokens, windowSize: 10, windowOverlap: 4);
        var text = WindowingTestHelpers.Words(200).Replace(" ", "   ", StringComparison.Ordinal);

        var windows = splitter.Split(text);

        windows.Select(w => CountWithWhitespaceTokens(text.AsSpan(w.Start, w.Length)))
            .Should().OnlyContain(tokens => tokens <= 10, "windows must fit by the real count");
        windows.SelectMany(w => text.Substring(w.Start, w.Length).Split(' ', StringSplitOptions.RemoveEmptyEntries)).Distinct()
            .Should().HaveCount(200);
    }

    [Fact]
    public void ShouldGiveUp_WhenTextNeedsMoreThanMaxWindows()
    {
        var splitter = new TextWindowSplitter(WindowingTestHelpers.CountWords, windowSize: 10, windowOverlap: 5);
        var text = WindowingTestHelpers.Words(100);
        var needed = splitter.Split(text).Count;

        splitter.TrySplit(text, needed - 1, out var tooFew).Should().BeFalse();
        tooFew.Should().BeEmpty();
        splitter.TrySplit(text, needed, out var enough).Should().BeTrue();
        enough.Should().HaveCount(needed);
        splitter.TrySplit(text, 0, out var unlimited).Should().BeTrue();
        unlimited.Should().HaveCount(needed);
    }

    [Fact]
    public void ShouldGiveUpWithoutCountingEveryWord_WhenTextCannotFitInMaxWindows()
    {
        var calls = 0;
        var splitter = new TextWindowSplitter(
            text =>
            {
                calls++;
                return WindowingTestHelpers.CountWords(text);
            },
            windowSize: 10,
            windowOverlap: 5);

        splitter.TrySplit(WindowingTestHelpers.Words(100_000), maxWindows: 10, out _).Should().BeFalse();
        calls.Should().Be(1, "the whole-text count already shows the limit is exceeded");
    }

    public static TheoryData<string> AwkwardInputs()
    {
        var prose = string.Join(" ", Enumerable.Repeat("The museum opens at nine, and the guided tour of the clock gallery starts at eleven.", 40));
        return new TheoryData<string>
        {
            prose,
            string.Concat(Enumerable.Repeat("博物馆九点开门，钟表馆的导览十一点开始。", 60)),
            Convert.ToBase64String(Enumerable.Range(0, 3000).Select(i => (byte)(i * 37 % 256)).ToArray()),
            string.Concat(Enumerable.Repeat("result=calculateTotal(items,taxRate)*discount;if(result>limit){notify(owner,result);}", 40)),
            string.Concat(Enumerable.Repeat("\U0001F600\U0001F680 wow \U0001F389", 150)),
            string.Join("\n\n\t  ", Enumerable.Repeat("short line", 300)),
            prose.Replace(" ", " ", StringComparison.Ordinal),
        };
    }

    [Theory]
    [MemberData(nameof(AwkwardInputs))]
    public void ShouldProduceWindowsThatFitTheRealTokenizer_WhenInputIsAwkward(string text)
    {
        // the Defender rule's WordPiece tokenizer, from the bundled vocab (no model is loaded)
        var tokenizer = BertTokenizer.Create(
            Path.Combine(AppContext.BaseDirectory, "defender-model", "vocab.txt"),
            new BertOptions { LowerCaseBeforeTokenization = true });
        var splitter = new TextWindowSplitter(span => tokenizer.CountTokens(span), windowSize: 64, windowOverlap: 32);

        var windows = splitter.Split(text);

        windows.Should().HaveCountGreaterThan(1);
        windows.Select(w => tokenizer.CountTokens(text.AsSpan(w.Start, w.Length)))
            .Should().OnlyContain(tokens => tokens <= 64, "no window may be truncated by the model");
        CoveredCharacters(text, windows).Should().Be(text.Count(c => !char.IsWhiteSpace(c)), "every character must be classified");
        for (var i = 0; i + 1 < windows.Count; i++)
            windows[i + 1].Start.Should().BeLessThan(windows[i].End, "consecutive windows overlap");
    }

    [Theory]
    [InlineData(0, 0)]
    [InlineData(10, 10)]
    [InlineData(10, 11)]
    [InlineData(10, -1)]
    public void ShouldThrow_WhenWindowSettingsAreInvalid(int windowSize, int windowOverlap)
    {
        var act = () => new TextWindowSplitter(WindowingTestHelpers.CountWords, windowSize, windowOverlap);

        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    private static (int First, int Last) WordRange(string text, TextWindow window)
    {
        var words = text.Substring(window.Start, window.Length).Split(' ');
        return (int.Parse(words[0][1..], CultureInfo.InvariantCulture),
            int.Parse(words[^1][1..], CultureInfo.InvariantCulture));
    }

    private static int CoveredCharacters(string text, IReadOnlyList<TextWindow> windows)
    {
        var covered = new bool[text.Length];
        foreach (var window in windows)
        {
            for (var i = window.Start; i < window.End; i++)
                covered[i] = true;
        }

        return Enumerable.Range(0, text.Length).Count(i => covered[i] && !char.IsWhiteSpace(text[i]));
    }
}
