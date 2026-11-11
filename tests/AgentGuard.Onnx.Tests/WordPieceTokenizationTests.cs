using FluentAssertions;
using Microsoft.ML.Tokenizers;
using Xunit;

namespace AgentGuard.Onnx.Tests;

/// <summary>
/// Unit tests for <see cref="WordPieceTokenization"/> against the Defender rule's real WordPiece
/// tokenizer (bundled vocab only, no model is loaded): the checks must agree with what the tokenizer
/// does when a session encodes text under a token limit.
/// </summary>
public class WordPieceTokenizationTests
{
    // the content-token budget of the Defender session at the default MaxTokenLength
    private const int Budget = 254;

    private const string Sentence = "The weather today is pleasant and the garden looks lovely.";

    private static readonly BertTokenizer Tokenizer = BertTokenizer.Create(
        Path.Combine(AppContext.BaseDirectory, "defender-model", "vocab.txt"),
        new BertOptions { LowerCaseBeforeTokenization = true });

    /// <summary>
    /// A 99-character word that counts as one unknown token, but only after the tokenizer has matched
    /// 98 one-letter pieces: the last character is in no piece of the vocabulary.
    /// </summary>
    internal static readonly string RoomHungryWord = string.Concat(Enumerable.Repeat("qxzj", 24)) + "qxꙮ";

    [Fact]
    public void ShouldCountTheRoomHungryWordAsOneToken()
    {
        // guards the fixture: the count gives no hint of the room the word needs while it is encoded
        Tokenizer.CountTokens(RoomHungryWord).Should().Be(1);
        Tokenizer.CountTokens(RoomHungryWord[..^1]).Should().Be(98);
    }

    [Fact]
    public void ShouldSayTextFits_WhenTheSessionEncodesAllOfIt()
    {
        var fits = WordPieceTokenization.EncodesWithin(Tokenizer, Budget);
        var text = string.Join(' ', Enumerable.Repeat(Sentence, 20));
        Tokenizer.CountTokens(text).Should().BeLessThanOrEqualTo(Budget);

        fits(text).Should().BeTrue();
        fits(RoomHungryWord).Should().BeTrue("on its own the word has all the room it needs");
        fits("").Should().BeTrue();
    }

    [Fact]
    public void ShouldSayTextDoesNotFit_WhenAWordRunsOutOfRoomAlthoughTheCountFits()
    {
        var fits = WordPieceTokenization.EncodesWithin(Tokenizer, Budget);
        var text = string.Join(' ', Enumerable.Repeat(Sentence, 18)) + " " + RoomHungryWord + " and more text after it";
        Tokenizer.CountTokens(text).Should().BeLessThanOrEqualTo(Budget, "the fixture needs a count that fits");

        // what the session does with it: stop at the word, losing it and everything after
        var encoded = Tokenizer.EncodeToIds(text, Budget, addSpecialTokens: false, out _, out _);
        encoded.Count.Should().BeLessThan(Tokenizer.CountTokens(text));

        fits(text).Should().BeFalse();
    }

    [Fact]
    public void ShouldSayTextDoesNotFit_WhenItHasMoreTokensThanTheBudget()
    {
        var fits = WordPieceTokenization.EncodesWithin(Tokenizer, Budget);
        var text = string.Join(' ', Enumerable.Repeat(Sentence, 40));

        fits(text).Should().BeFalse();
    }

    [Fact]
    public void ShouldSayTextFits_WhenItFillsTheBudgetExactly()
    {
        var text = string.Join(' ', Enumerable.Repeat(Sentence, 5));
        var fits = WordPieceTokenization.EncodesWithin(Tokenizer, Tokenizer.CountTokens(text));

        fits(text).Should().BeTrue();
    }

    [Theory]
    [InlineData("ordinary words in a sentence")]
    [InlineData("a,long,run,of,short,words,joined,by,punctuation,that,the,tokenizer,splits,itself,into,many,short,words,so,all,of,it,is,seen")]
    [InlineData("")]
    public void ShouldSayEveryWordIsSeen_WhenNoWordIsOverTheLimit(string text)
    {
        WordPieceTokenization.WordsWithinLimit(Tokenizer)(text).Should().BeTrue();
    }

    [Fact]
    public void ShouldSayEveryWordIsSeen_WhenAWordIsExactlyAtTheLimit()
    {
        var seesEveryWord = WordPieceTokenization.WordsWithinLimit(Tokenizer);

        seesEveryWord(new string('a', Tokenizer.MaxInputCharsPerWord)).Should().BeTrue();
        seesEveryWord(new string('a', Tokenizer.MaxInputCharsPerWord + 1)).Should().BeFalse();
    }

    [Fact]
    public void ShouldSayAWordIsNotSeen_WhenLineBreaksJoinShortWordsPastTheLimit()
    {
        var seesEveryWord = WordPieceTokenization.WordsWithinLimit(Tokenizer);
        var text = string.Join("\n", Enumerable.Repeat("line", 30));

        // guards the fixture: the tokenizer reads past line breaks, so this is one 120-character word
        Tokenizer.EncodeToIds(text, addSpecialTokens: false).Should().Equal(Tokenizer.UnknownTokenId);

        seesEveryWord(text).Should().BeFalse();
        seesEveryWord(text.Replace('\n', ' ')).Should().BeTrue();
    }

    [Fact]
    public void ShouldAgreeWithTheTokenizer_AboutWhichLongWordsBecomeUnknown()
    {
        var seesEveryWord = WordPieceTokenization.WordsWithinLimit(Tokenizer);

        foreach (var length in new[] { 50, 99, 100, 101, 150 })
        {
            var word = new string('a', length);
            var isUnknown = Tokenizer.EncodeToIds(word, addSpecialTokens: false) is [var id] && id == Tokenizer.UnknownTokenId;

            seesEveryWord(word).Should().Be(!isUnknown, $"a word of {length} characters");
        }
    }
}
