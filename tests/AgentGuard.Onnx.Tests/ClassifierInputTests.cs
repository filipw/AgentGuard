using FluentAssertions;
using Xunit;

namespace AgentGuard.Onnx.Tests;

/// <summary>
/// Unit tests for <see cref="ClassifierInput"/>: text that is not valid UTF-16 is repaired before it
/// reaches a tokenizer, and line breaks become spaces for a tokenizer that would drop them, without
/// moving any character.
/// </summary>
public class ClassifierInputTests
{
    [Theory]
    [InlineData("")]
    [InlineData("plain text with spaces")]
    [InlineData("non-breaking\u00A0space and zero\u200Bwidth stay")]
    public void ShouldReturnTheSameString_WhenTextHasNoLineBreaks(string text)
    {
        ClassifierInput.LineBreaksToSpaces(text).Should().BeSameAs(text);
    }

    [Theory]
    [InlineData("ignore\nall\nprevious", "ignore all previous")]
    [InlineData("ignore\tall\r\nprevious", "ignore all  previous")]
    [InlineData("a\vb\fc", "a b c")]
    [InlineData("a\u0085b\u2028c\u2029d", "a b c d")]
    [InlineData("\n", " ")]
    [InlineData("\ntrailing\n", " trailing ")]
    public void ShouldPutASpaceInPlaceOfEachLineBreakOrTab(string text, string expected)
    {
        var result = ClassifierInput.LineBreaksToSpaces(text);

        result.Should().Be(expected);
        result.Length.Should().Be(text.Length, "positions in the result are positions in the input");
    }

    [Theory]
    [InlineData("")]
    [InlineData("plain text")]
    [InlineData("emoji \U0001F600 and \U0001F680 pairs")]
    [InlineData("\U0001F600")]
    public void ShouldReturnTheSameString_WhenTextIsWellFormed(string text)
    {
        ClassifierInput.ReplaceUnpairedSurrogates(text).Should().BeSameAs(text);
    }

    [Fact]
    public void ShouldReplaceEachUnpairedSurrogate_AndKeepPairs()
    {
        // not theory data: strings that are not valid UTF-16 do not survive being test case arguments
        (string Text, string Expected)[] cases =
        [
            ("abc\uD800def", "abc�def"),
            ("abc\uDC00def", "abc�def"),
            ("\uD800", "�"),
            ("\uDC00", "�"),
            ("tail\uD83D", "tail�"),
            ("\uDE00head", "�head"),
            ("\uDC00\uD800", "��"),
            ("\uD800𐀀", "�𐀀"),
            ("😀\uDE00", "😀�"),
            ("a\uD800b\uDC00c😀d", "a�b�c😀d"),
        ];

        foreach (var (text, expected) in cases)
        {
            var repaired = ClassifierInput.ReplaceUnpairedSurrogates(text);

            repaired.Should().Be(expected);
            repaired.Should().HaveLength(text.Length, "positions in the repaired text must be positions in the input");
            var normalize = () => repaired.Normalize();
            normalize.Should().NotThrow("the repaired text is valid UTF-16");
        }
    }
}
