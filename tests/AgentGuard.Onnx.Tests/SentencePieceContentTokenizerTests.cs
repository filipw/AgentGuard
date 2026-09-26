using FluentAssertions;
using Microsoft.ML.Tokenizers;
using Xunit;

namespace AgentGuard.Onnx.Tests;

/// <summary>
/// The SentencePiece tokenizer shared by the DeBERTa, PIGuard and Opir rules must emit content ids
/// only, because Kyoto's sessions add <c>[CLS]</c>/<c>[SEP]</c> (or the label prefix and <c>[SEP]</c>)
/// themselves. Tested against a hand-built model with the DeBERTa v3 special-token layout.
/// </summary>
public sealed class SentencePieceContentTokenizerTests : IDisposable
{
    private readonly string _modelPath = SentencePieceTestModel.WriteToTempFile();

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

    public void Dispose() => File.Delete(_modelPath);
}
