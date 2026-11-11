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

    /// <summary>
    /// Wraps a session's classify call so that text whose normalized form is much longer than the
    /// text itself can be encoded.
    /// </summary>
    /// <remarks>
    /// Kyoto's sessions encode with a token limit, and on that path Microsoft.ML.Tokenizers 2.0.0 sizes
    /// the buffer for the normalized text from the input length and grows it only once. Characters the
    /// model's normalization expands a lot (U+FDFA becomes 18 characters) overflow it, and the encode
    /// throws <see cref="IndexOutOfRangeException"/>. Trailing spaces make the input, and with it the
    /// buffer, long enough; the normalizer strips them again, so the token ids are those of the
    /// original text.
    /// </remarks>
    /// <param name="tokenizer">A tokenizer loaded from the same model file as the session's.</param>
    /// <param name="classify">The session's classify call.</param>
    /// <typeparam name="TScore">The classifier's score type.</typeparam>
    public static Func<string, TScore> WithRoomForNormalization<TScore>(SentencePieceTokenizer tokenizer, Func<string, TScore> classify) =>
        text => classify(PadForNormalization(tokenizer, text));

    /// <summary>
    /// Returns <paramref name="text"/> padded with trailing spaces to the length of its normalized
    /// form, or <paramref name="text"/> itself when the tokenizer's buffer is large enough already or
    /// the normalizer would keep the padding.
    /// </summary>
    /// <param name="tokenizer">The tokenizer whose normalization applies.</param>
    /// <param name="text">The text to encode.</param>
    public static string PadForNormalization(SentencePieceTokenizer tokenizer, string text)
    {
        // counting without a token limit does not use the undersized buffer, and reports the
        // normalized length as the characters it consumed
        tokenizer.CountTokens(
            text,
            addBeginningOfSentence: false,
            addEndOfSentence: false,
            considerPreTokenization: true,
            considerNormalization: true,
            out _,
            out var normalizedLength);

        if (normalizedLength <= text.Length + BufferHeadroom
            || tokenizer.Normalizer is not SentencePieceNormalizer { RemoveExtraWhiteSpaces: true })
        {
            return text;
        }

        return text.PadRight(normalizedLength);
    }

    // the tokenizer's buffer holds at least this many characters more than the input
    private const int BufferHeadroom = 2;
}
