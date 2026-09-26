using Microsoft.ML.Tokenizers;

namespace AgentGuard.Onnx;

/// <summary>
/// Loads the SentencePiece tokenizer of a DeBERTa-family classifier so that it emits content ids only.
/// </summary>
/// <remarks>
/// Kyoto's sessions add the special tokens themselves: <c>[CLS]</c> and <c>[SEP]</c> around the input,
/// or the label prefix and <c>[SEP]</c>. In the DeBERTa v3 vocabularies the beginning-of-sentence id is
/// the <c>[CLS]</c> id, so a tokenizer that also adds it would put <c>[CLS]</c> into every input twice.
/// </remarks>
internal static class SentencePieceContentTokenizer
{
    /// <summary>Loads the SentencePiece model at <paramref name="path"/> without BOS or EOS tokens.</summary>
    /// <param name="path">Path to the SentencePiece model file (<c>spm.model</c>).</param>
    /// <returns>A tokenizer that encodes text into content ids only.</returns>
    public static SentencePieceTokenizer Load(string path)
    {
        using var stream = File.OpenRead(path);
        return SentencePieceTokenizer.Create(stream, addBeginningOfSentence: false, addEndOfSentence: false);
    }
}
