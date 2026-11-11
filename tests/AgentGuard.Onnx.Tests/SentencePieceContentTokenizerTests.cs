using FluentAssertions;
using Microsoft.ML.Tokenizers;
using Xunit;

namespace AgentGuard.Onnx.Tests;

/// <summary>
/// The SentencePiece tokenizer shared by the DeBERTa, PIGuard and Opir rules must emit content ids
/// only, because Kyoto's sessions add <c>[CLS]</c>/<c>[SEP]</c> (or the label prefix and <c>[SEP]</c>)
/// themselves. Tested against a hand-built model with the DeBERTa v3 special-token layout. The
/// sessions encode with a token limit, which must also work for text whose normalized form is much
/// longer than the text; that is tested against a variant of the model whose normalization expands a
/// character, as the NFKC rules of the real models do.
/// </summary>
public sealed class SentencePieceContentTokenizerTests : IDisposable
{
    // the content-token limit Kyoto's sessions encode with at the default MaxTokenLength
    private const int SessionTokenLimit = 510;

    private readonly string _modelPath = SentencePieceTestModel.WriteToTempFile();
    private readonly string _expandingModelPath = SentencePieceTestModel.WriteToTempFile(expanding: true);

    [Fact]
    public void ShouldAddClsAsBos_WhenCreatedWithTheLibraryDefaults()
    {
        // guards the fixture: in the DeBERTa v3 layout the BOS id is the [CLS] id, which is what makes
        // a tokenizer created with the defaults put [CLS] into the session input twice
        using var stream = File.OpenRead(_modelPath);
        var tokenizer = SentencePieceTokenizer.Create(stream);

        tokenizer.EncodeToIds("hello world").Should().Equal(
            SentencePieceTestModel.ClsId, SentencePieceTestModel.HelloId, SentencePieceTestModel.WorldId);
    }

    [Fact]
    public void ShouldEmitContentIdsOnly_WhenLoadingADebertaStyleModel()
    {
        var tokenizer = SentencePieceContentTokenizer.Load(_modelPath);

        tokenizer.AddBeginningOfSentence.Should().BeFalse();
        tokenizer.AddEndOfSentence.Should().BeFalse();
        tokenizer.EncodeToIds("hello world").Should().Equal(SentencePieceTestModel.HelloId, SentencePieceTestModel.WorldId);
    }

    [Fact]
    public void ShouldPutClsIntoTheSessionInputOnce_WhenTheSessionAddsItsOwnSpecialTokens()
    {
        var tokenizer = SentencePieceContentTokenizer.Load(_modelPath);

        // built the way Kyoto's OnnxModelSession builds the model input: [CLS] + content ids + [SEP]
        var content = tokenizer.EncodeToIds("hello world", 512 - 2, out _, out _);
        int[] input = [SentencePieceTestModel.ClsId, .. content, SentencePieceTestModel.SepId];

        input.Should().Equal(
            SentencePieceTestModel.ClsId, SentencePieceTestModel.HelloId, SentencePieceTestModel.WorldId, SentencePieceTestModel.SepId);
    }

    [Fact]
    public void ShouldLeaveTheWholeSessionBudgetToContent_WhenTokenizerAddsNoSpecialTokens()
    {
        var tokenizer = SentencePieceContentTokenizer.Load(_modelPath);

        WindowedClassification.OnnxSessionContentBudget(tokenizer, 512).Should().Be(510, "only the session's [CLS] and [SEP] take room");
        WindowedClassification.CountContentTokens(tokenizer)("hello world").Should().Be(2);
    }

    [Fact]
    public void ShouldOverflowInTheLibrary_WhenShortTextExpandsUnderNormalizationAndIsEncodedWithATokenLimit()
    {
        // guards the fixture: this is the tokenizer failure the padding exists for. Encoding with a
        // limit keeps the normalized text in a buffer sized from the input; counting does not.
        var tokenizer = SentencePieceContentTokenizer.Load(_expandingModelPath);
        var text = new string(SentencePieceTestModel.ExpandingCharacter, 2);

        var encodeWithLimit = () => tokenizer.EncodeToIds(text, SessionTokenLimit, out _, out _);

        encodeWithLimit.Should().Throw<IndexOutOfRangeException>();
        tokenizer.EncodeToIds(text, addBeginningOfSentence: false, addEndOfSentence: false).Should().NotBeEmpty();
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(5)]
    [InlineData(40)]
    [InlineData(400)]
    public void ShouldEncodeExpandingTextWithATokenLimit_WhenPaddedForNormalization(int expandingCharacters)
    {
        var tokenizer = SentencePieceContentTokenizer.Load(_expandingModelPath);
        var text = "hello " + new string(SentencePieceTestModel.ExpandingCharacter, expandingCharacters) + " world";
        var expected = tokenizer.EncodeToIds(text, addBeginningOfSentence: false, addEndOfSentence: false);

        var padded = SentencePieceContentTokenizer.PadForNormalization(tokenizer, text);
        var ids = tokenizer.EncodeToIds(padded, int.MaxValue - 1, out _, out _);

        ids.Should().Equal(expected, "the padding must not change what the model sees");
        padded.TrimEnd(' ').Should().Be(text);
    }

    [Fact]
    public void ShouldTruncateLikeTheUnpaddedText_WhenPaddedTextExceedsTheTokenLimit()
    {
        var tokenizer = SentencePieceContentTokenizer.Load(_expandingModelPath);
        var text = new string(SentencePieceTestModel.ExpandingCharacter, 3);
        var all = tokenizer.EncodeToIds(text, addBeginningOfSentence: false, addEndOfSentence: false);

        var ids = tokenizer.EncodeToIds(SentencePieceContentTokenizer.PadForNormalization(tokenizer, text), 5, out _, out _);

        ids.Should().Equal(all.Take(5));
    }

    [Theory]
    [InlineData("hello world")]
    [InlineData("  hello   world  ")]
    [InlineData("h")]
    public void ShouldLeaveTextAlone_WhenNormalizationDoesNotExpandIt(string text)
    {
        var tokenizer = SentencePieceContentTokenizer.Load(_expandingModelPath);

        SentencePieceContentTokenizer.PadForNormalization(tokenizer, text).Should().BeSameAs(text);
    }

    [Fact]
    public void ShouldClassifyExpandingText_WhenTheSessionEncodesWithATokenLimit()
    {
        var tokenizer = SentencePieceContentTokenizer.Load(_expandingModelPath);
        var text = new string(SentencePieceTestModel.ExpandingCharacter, 2);

        // encodes the way Kyoto's sessions do before running the model
        var classify = SentencePieceContentTokenizer.WithRoomForNormalization(
            tokenizer, input => tokenizer.EncodeToIds(input, SessionTokenLimit, out _, out _).Count);

        classify(text).Should().Be(WindowedClassification.CountContentTokens(tokenizer)(text));
    }

    public void Dispose()
    {
        File.Delete(_modelPath);
        File.Delete(_expandingModelPath);
    }
}
