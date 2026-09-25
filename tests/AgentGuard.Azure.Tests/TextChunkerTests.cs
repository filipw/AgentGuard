using System.Text;
using FluentAssertions;
using Xunit;

namespace AgentGuard.Azure.Tests;

public class TextChunkerTests
{
    private static string Words(int length)
    {
        var words = new[] { "lorem", "ipsum", "dolor", "sit", "amet", "consectetur", "adipiscing", "elit" };
        var builder = new StringBuilder(length + 16);
        for (var i = 0; builder.Length < length; i++)
            builder.Append(words[i % words.Length]).Append(' ');

        return builder.ToString(0, length);
    }

    [Fact]
    public void ShouldReturnOneWindow_WhenTextFits()
    {
        TextChunker.Split("hello world", maxLength: 100, overlap: 10)
            .Should().Equal(new TextWindow(0, 11));
    }

    [Theory]
    [InlineData(10_000, 1_000, 100)]
    [InlineData(25_000, 10_000, 2_000)]
    [InlineData(12_345, 5_000, 500)]
    public void ShouldCoverTheTextWithOverlappingWindowsWithinTheLimit_WhenTextIsLong(int length, int maxLength, int overlap)
    {
        var text = Words(length);

        var windows = TextChunker.Split(text, maxLength, overlap);

        windows.Should().HaveCountGreaterThan(1);
        windows[0].Start.Should().Be(0);
        (windows[^1].Start + windows[^1].Length).Should().Be(text.Length);
        windows.Should().OnlyContain(w => w.Length > 0 && w.Length <= maxLength);

        for (var i = 1; i < windows.Count; i++)
        {
            var previousEnd = windows[i - 1].Start + windows[i - 1].Length;
            windows[i].Start.Should().BeGreaterThan(windows[i - 1].Start);
            windows[i].Start.Should().BeLessThanOrEqualTo(previousEnd - overlap, "consecutive windows overlap by at least the requested amount");
        }
    }

    [Fact]
    public void ShouldPutEverySpanUpToTheOverlapWhollyInsideSomeWindow_WhenTextIsLong()
    {
        const int maxLength = 500;
        const int overlap = 100;
        var text = Words(3_000);

        var windows = TextChunker.Split(text, maxLength, overlap);

        for (var start = 0; start + overlap <= text.Length; start++)
        {
            var end = start + overlap;
            windows.Should().Contain(w => w.Start <= start && end <= w.Start + w.Length,
                $"the span [{start}, {end}) must lie whole inside one window");
        }
    }

    [Fact]
    public void ShouldCutRightAfterWhitespace_WhenThereIsSomeNearTheLimit()
    {
        var text = Words(20_000);

        var windows = TextChunker.Split(text, 10_000, 1_000);

        foreach (var window in windows.Take(windows.Count - 1))
            char.IsWhiteSpace(text[window.Start + window.Length - 1]).Should().BeTrue();

        foreach (var window in windows.Skip(1))
            char.IsWhiteSpace(text[window.Start - 1]).Should().BeTrue();
    }

    [Fact]
    public void ShouldPreferALineBreak_WhenOneIsNearTheLimit()
    {
        // a line break 300 units before the limit wins over the spaces closer to it
        var text = Words(9_700) + "\n" + Words(15_000);

        var windows = TextChunker.Split(text, 10_000, 1_000);

        windows[0].Length.Should().Be(9_701);
        text[windows[0].Length - 1].Should().Be('\n');
    }

    [Fact]
    public void ShouldNeverSplitASurrogatePair_WhenTextHasNoWhitespace()
    {
        var text = string.Concat(Enumerable.Repeat("\U0001F600", 12_000));

        var windows = TextChunker.Split(text, 10_001, 1_001);

        windows.Should().HaveCountGreaterThan(1);
        foreach (var window in windows)
        {
            char.IsLowSurrogate(text[window.Start]).Should().BeFalse("a window must not start inside a surrogate pair");
            char.IsHighSurrogate(text[window.Start + window.Length - 1]).Should().BeFalse("a window must not end inside a surrogate pair");
        }
    }

    [Fact]
    public void ShouldCutAtTheLimit_WhenTextHasNoWhitespace()
    {
        var text = new string('x', 25_000);

        var windows = TextChunker.Split(text, 10_000, 2_000);

        windows.Should().Equal(new TextWindow(0, 10_000), new TextWindow(8_000, 10_000), new TextWindow(16_000, 9_000));
    }

    [Fact]
    public void ShouldLeaveOutWhitespaceOnlyWindows_WhenSplittingToStrings()
    {
        var text = "first part" + new string(' ', 30_000) + "last part";

        var parts = TextChunker.SplitToStrings(text, 10_000, 1_000).ToList();

        parts.Should().HaveCount(2);
        parts[0].Should().StartWith("first part");
        parts[1].Should().EndWith("last part");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   \n\t ")]
    public void ShouldYieldNothing_WhenTextIsNullOrWhitespace(string? text)
    {
        TextChunker.SplitToStrings(text, 10_000, 1_000).Should().BeEmpty();
    }

    [Fact]
    public void ShouldReturnTheSameString_WhenTextFits()
    {
        const string text = "a short prompt";

        TextChunker.SplitToStrings(text, 10_000, 1_000).Should().ContainSingle().Which.Should().BeSameAs(text);
    }

    [Theory]
    [InlineData(100, 50)]
    [InlineData(1_000, 400)]
    [InlineData(10, -1)]
    public void ShouldThrow_WhenTheOverlapLeavesNoRoomToAdvance(int maxLength, int overlap)
    {
        var act = () => TextChunker.Split(new string('x', 5_000), maxLength, overlap);

        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Theory]
    [InlineData("abc", 3, true)]
    [InlineData("abc", 4, false)]
    [InlineData("ééé", 3, true)]
    [InlineData("ééé", 4, false)]
    public void ShouldCountTextElements_WhenCheckingAMinimumLength(string text, int count, bool expected)
    {
        TextChunker.HasAtLeastTextElements(text, count).Should().Be(expected);
    }

    [Fact]
    public void ShouldCountASurrogatePairAsOneCharacter_WhenCheckingAMinimumLength()
    {
        // 110 emoji are 220 UTF-16 code units but only 110 characters
        var text = string.Concat(Enumerable.Repeat("\U0001F600", 110));

        TextChunker.HasAtLeastTextElements(text, 110).Should().BeTrue();
        TextChunker.HasAtLeastTextElements(text, 111).Should().BeFalse();
    }
}
