using Microsoft.ML.Tokenizers;

namespace AgentGuard.Onnx;

/// <summary>
/// Checks that keep text from getting lost in the WordPiece tokenizer of the Defender classifier: both
/// answer, with the tokenizer itself, whether it would encode all of a piece of text.
/// </summary>
internal static class WordPieceTokenization
{
    // Unicode composition (NFC), the last step of BERT normalization, can make text up to three
    // times as long in UTF-16
    private const int MaxNormalizationGrowth = 3;

    /// <summary>
    /// Creates the check that a session with room for <paramref name="contentTokenBudget"/> content
    /// tokens encodes a text completely.
    /// </summary>
    /// <remarks>
    /// A token count within the budget does not guarantee that. WordPiece matches a word piece by
    /// piece and only at its end finds that the word is unknown and counts as one token; when the
    /// pieces matched up to there exceed the room left under the limit, encoding stops at that word
    /// and everything after it is dropped. So the check encodes under the limit and compares the
    /// result with the unlimited count.
    /// </remarks>
    /// <param name="tokenizer">A tokenizer configured like the session's.</param>
    /// <param name="contentTokenBudget">Content tokens the session encodes, excluding the special tokens it adds.</param>
    public static SessionFitCheck EncodesWithin(BertTokenizer tokenizer, int contentTokenBudget)
    {
        ArgumentNullException.ThrowIfNull(tokenizer);
        ArgumentOutOfRangeException.ThrowIfLessThan(contentTokenBudget, 1);

        return text =>
            tokenizer.EncodeToIds(text, contentTokenBudget, addSpecialTokens: false, out _, out _).Count
            == tokenizer.CountTokens(text);
    }

    /// <summary>
    /// Creates the check that no word of a text exceeds the tokenizer's per-word length limit
    /// (<see cref="WordPieceTokenizer.MaxInputCharsPerWord"/>). A longer word is not encoded at all: it
    /// becomes a single unknown token. Words are measured the way the tokenizer forms them, after its
    /// own normalization and word splitting.
    /// </summary>
    /// <param name="tokenizer">A tokenizer configured like the session's.</param>
    public static WordVisibilityCheck WordsWithinLimit(BertTokenizer tokenizer)
    {
        ArgumentNullException.ThrowIfNull(tokenizer);

        var limit = tokenizer.MaxInputCharsPerWord;
        var normalizer = tokenizer.Normalizer;
        var preTokenizer = tokenizer.PreTokenizer;

        return text =>
        {
            // too short to hold a word over the limit, whatever normalization does to it
            if (text.Length <= limit / MaxNormalizationGrowth)
                return true;

            var normalized = normalizer is null ? text.ToString() : normalizer.Normalize(text);
            if (preTokenizer is null)
                return normalized.Length <= limit;

            foreach (var (_, length) in preTokenizer.PreTokenize(normalized))
            {
                if (length > limit)
                    return false;
            }

            return true;
        };
    }
}
