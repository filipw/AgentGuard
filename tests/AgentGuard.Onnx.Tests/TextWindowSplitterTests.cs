using System.Globalization;
using FluentAssertions;
using Microsoft.ML.Tokenizers;
using Xunit;

namespace AgentGuard.Onnx.Tests;

/// <summary>
/// Unit tests for <see cref="TextWindowSplitter"/>. Most use simple word- and character-based token
/// counters so the windowing logic is verified in isolation; the property tests run it with the
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

    // session fit: a session can stop short of the end of a window whose token count fits. The fake
    // session below has room for ten units; a word takes one, a word starting with BIG takes five.

    [Fact]
    public void ShouldNotUseASingleWindow_WhenTheCountFitsButTheSessionWouldStopEarly()
    {
        var splitter = new TextWindowSplitter(WindowingTestHelpers.CountWords, windowSize: 8, windowOverlap: 2, HasRoomFor(10));
        const string text = "w0 w1 w2 w3 BIG4 BIG5 w6";

        var windows = splitter.Split(text);

        windows.Should().HaveCountGreaterThan(1, "seven words fit the window, but need fifteen units of room");
        Texts(text, windows).Should().OnlyContain(window => RoomNeeded(window) <= 10);
        Texts(text, windows).SelectMany(window => window.Split(' ')).Distinct().Should().BeEquivalentTo(text.Split(' '));
    }

    [Fact]
    public void ShouldKeepEveryWindowWithinWhatTheSessionEncodes_WhenWordsNeedMoreRoomThanTheirCount()
    {
        var splitter = new TextWindowSplitter(WindowingTestHelpers.CountWords, windowSize: 8, windowOverlap: 2, HasRoomFor(10));
        var words = Enumerable.Range(0, 200).Select(i => i % 7 == 3 || i % 11 == 0 ? $"BIG{i}" : $"w{i}").ToArray();
        var text = string.Join(' ', words);

        var windows = splitter.Split(text);

        Texts(text, windows).Should().OnlyContain(
            window => WindowingTestHelpers.CountWords(window) <= 8 && RoomNeeded(window) <= 10,
            "no window may be cut short by the session");
        Texts(text, windows).SelectMany(window => window.Split(' ')).Distinct().Should().HaveCount(200, "no word may be left out");
        windows.Should().OnlyHaveUniqueItems("a window that adds nothing is not classified again");
    }

    [Fact]
    public void ShouldGiveTheSameWindows_WhenTheSessionEncodesEveryWindowWhole()
    {
        var text = WindowingTestHelpers.Words(300);
        var plain = new TextWindowSplitter(WindowingTestHelpers.CountWords, windowSize: 10, windowOverlap: 4);
        var withCheck = new TextWindowSplitter(WindowingTestHelpers.CountWords, windowSize: 10, windowOverlap: 4, _ => true);

        withCheck.Split(text).Should().Equal(plain.Split(text));
    }

    [Fact]
    public void ShouldClassifyAWordInSlices_WhenItAloneDoesNotFitTheSession()
    {
        // a session with room for six characters
        var splitter = new TextWindowSplitter(
            WindowingTestHelpers.CountWords, windowSize: 4, windowOverlap: 1, text => WindowingTestHelpers.CountNonWhitespaceChars(text) <= 6);
        const string text = "ab cd abcdefghijklmnopqrstuvwxyz ef gh";

        var windows = splitter.Split(text);

        Texts(text, windows).Should().OnlyContain(window => WindowingTestHelpers.CountNonWhitespaceChars(window) <= 6);
        CoveredCharacters(text, windows).Should().Be(text.Count(c => !char.IsWhiteSpace(c)), "every character must be classified");
    }

    [Fact]
    public void ShouldKeepSurrogatePairsWhole_WhenSlicingAWord()
    {
        // a session with room for two characters, each emoji being one
        var splitter = new TextWindowSplitter(
            WindowingTestHelpers.CountWords, windowSize: 4, windowOverlap: 1, text => text.ToString().EnumerateRunes().Count() <= 2);
        var text = string.Concat(Enumerable.Repeat("\U0001F600", 7));

        var windows = splitter.Split(text);

        Texts(text, windows).Should().OnlyContain(window => !char.IsLowSurrogate(window[0]) && !char.IsHighSurrogate(window[window.Length - 1]));
        windows.Sum(window => window.Length).Should().Be(text.Length);
    }

    [Fact]
    public void ShouldThrow_WhenASingleCharacterDoesNotFitTheSession()
    {
        var splitter = new TextWindowSplitter(
            WindowingTestHelpers.CountWords, windowSize: 4, windowOverlap: 1, text => !text.Contains('!'));

        var act = () => splitter.Split("ab cd e!f gh");

        act.Should().Throw<InvalidOperationException>("no window can hold that character, so it cannot be classified");
    }

    [Fact]
    public void ShouldGiveUp_WhenSlicesTakeMoreThanMaxWindows()
    {
        var splitter = new TextWindowSplitter(
            WindowingTestHelpers.CountWords, windowSize: 4, windowOverlap: 1, text => WindowingTestHelpers.CountNonWhitespaceChars(text) <= 2);
        const string text = "abcdefghijklmnopqrstuvwxyz";

        splitter.TrySplit(text + " " + text, maxWindows: 5, out var windows).Should().BeFalse();
        windows.Should().BeEmpty();
        splitter.TrySplit(text, maxWindows: 0, out windows).Should().BeTrue();
        windows.Should().HaveCountGreaterThan(5);
    }

    [Theory]
    [InlineData(256, 254, 32)]
    [InlineData(256, 200, 32)]
    [InlineData(256, 64, 32)]
    [InlineData(34, 32, 8)]
    public void ShouldProduceWindowsTheRealSessionEncodesWhole_WhenWordsNeedMoreRoomThanTheirCount(
        int maxTokenLength, int windowSize, int windowOverlap)
    {
        // the Defender rule's WordPiece tokenizer, from the bundled vocab (no model is loaded)
        var tokenizer = BertTokenizer.Create(
            Path.Combine(AppContext.BaseDirectory, "defender-model", "vocab.txt"),
            new BertOptions { LowerCaseBeforeTokenization = true });
        var budget = maxTokenLength - 2;
        var fits = WordPieceTokenization.EncodesWithin(tokenizer, budget);
        var splitter = new TextWindowSplitter(span => tokenizer.CountTokens(span), windowSize, windowOverlap, fits);
        const string sentence = "The museum opens at nine, and the guided tour of the clock gallery starts at eleven.";
        var text = string.Join(
            " ",
            Enumerable.Range(0, 60).Select(i => i % 4 == 3 ? WordPieceTokenizationTests.RoomHungryWord : sentence));

        var windows = splitter.Split(text);

        foreach (var window in Texts(text, windows))
        {
            tokenizer.CountTokens(window).Should().BeLessThanOrEqualTo(windowSize);
            tokenizer.EncodeToIds(window, budget, addSpecialTokens: false, out _, out _).Count
                .Should().Be(tokenizer.CountTokens(window), "the session must encode the whole window");
        }

        CoveredCharacters(text, windows).Should().Be(text.Count(c => !char.IsWhiteSpace(c)), "every character must be classified");
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

    private static SessionFitCheck HasRoomFor(int room) => text => RoomNeeded(text) <= room;

    private static int RoomNeeded(ReadOnlySpan<char> text)
    {
        var room = 0;
        foreach (var word in text.ToString().Split(' ', StringSplitOptions.RemoveEmptyEntries))
            room += word.StartsWith("BIG", StringComparison.Ordinal) ? 5 : 1;
        return room;
    }

    private static List<string> Texts(string text, IReadOnlyList<TextWindow> windows) =>
        windows.Select(window => text.Substring(window.Start, window.Length)).ToList();

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
