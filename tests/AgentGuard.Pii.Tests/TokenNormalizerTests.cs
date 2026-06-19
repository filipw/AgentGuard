using AgentGuard.Pii.Analyzer.Context;
using FluentAssertions;
using Xunit;

namespace AgentGuard.Pii.Tests;

public class TokenNormalizerTests
{
    private static readonly EnglishTokenNormalizer Normalizer = new();

    [Theory]
    [InlineData("caresses", "caress")]
    [InlineData("ponies", "poni")]
    [InlineData("cats", "cat")]
    [InlineData("agreed", "agre")]
    [InlineData("plastered", "plaster")]
    [InlineData("motoring", "motor")]
    [InlineData("sing", "sing")]
    [InlineData("happy", "happi")]
    [InlineData("relational", "relat")]
    [InlineData("conditional", "condit")]
    [InlineData("rational", "ration")]
    [InlineData("digitizer", "digit")]
    [InlineData("security", "secur")]
    public void ShouldStem_WhenWordHasSuffix(string input, string expected)
    {
        Normalizer.Normalize(input).Should().Be(expected);
    }

    [Fact]
    public void ShouldLowercase_WhenNormalizing()
    {
        Normalizer.Normalize("RUNNING").Should().Be("run");
    }

    [Fact]
    public void ShouldReturnDigitsUnchanged_WhenTokenHasNoLetters()
    {
        Normalizer.Normalize("234567890").Should().Be("234567890");
    }

    [Theory]
    [InlineData("the", true)]
    [InlineData("is", true)]
    [InlineData("and", true)]
    [InlineData("passport", false)]
    [InlineData("account", false)]
    public void ShouldIdentifyStopWords(string token, bool expected)
    {
        Normalizer.IsStopWord(token).Should().Be(expected);
    }

    [Theory]
    [InlineData(".", true)]
    [InlineData(":", true)]
    [InlineData("#", true)]
    [InlineData("word", false)]
    [InlineData("a1", false)]
    public void ShouldIdentifyPunctuation(string token, bool expected)
    {
        Normalizer.IsPunctuation(token).Should().Be(expected);
    }

    [Fact]
    public void ShouldReportOffsets_WhenTokenizing()
    {
        var tokens = Normalizer.Tokenize("my ssn is 234-56-7890");

        tokens.Select(t => t.Token).Should().ContainInOrder("my", "ssn", "is", "234", "-", "56", "-", "7890");

        var first = tokens[0];
        first.Start.Should().Be(0);
        first.End.Should().Be(2);

        // offsets must map back to the original text
        foreach (var (token, start, end) in tokens)
        {
            "my ssn is 234-56-7890"[start..end].Should().Be(token);
        }
    }
}
