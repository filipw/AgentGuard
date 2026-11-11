using System.Buffers;

namespace AgentGuard.Onnx;

/// <summary>Makes input text safe to hand to the tokenizers of the ONNX classifier rules.</summary>
internal static class ClassifierInput
{
    private const char ReplacementCharacter = '�';

    // tab, line feed, vertical tab, form feed, carriage return, next line, line and paragraph separator
    private static readonly SearchValues<char> LineBreaks = SearchValues.Create("\t\n\v\f\r\u0085\u2028\u2029");

    /// <summary>
    /// Replaces every surrogate code unit that is not part of a pair with U+FFFD, the character
    /// Unicode reserves for exactly that. Such a string is not valid UTF-16 and the tokenizers throw on
    /// it. The result has the same length, so character positions in it are positions in the input.
    /// </summary>
    /// <param name="text">The input text.</param>
    /// <returns><paramref name="text"/> itself when it is well-formed, otherwise a repaired copy.</returns>
    public static string ReplaceUnpairedSurrogates(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        var first = IndexOfUnpairedSurrogate(text, 0);
        if (first < 0)
            return text;

        return string.Create(text.Length, (text, first), static (destination, state) =>
        {
            var (source, index) = state;
            source.CopyTo(destination);
            while (index >= 0)
            {
                destination[index] = ReplacementCharacter;
                index = IndexOfUnpairedSurrogate(source, index + 1);
            }
        });
    }

    /// <summary>
    /// Replaces line breaks, tabs and the other one-character line and page separators with a space.
    /// The result has the same length, so character positions in it are positions in the input.
    /// </summary>
    /// <remarks>
    /// For tokenizers that drop these characters instead of treating them as word boundaries: the BERT
    /// normalizer of Microsoft.ML.Tokenizers removes them as control characters, which joins the last
    /// word of a line to the first word of the next, where the reference BERT tokenizer a model was
    /// trained with reads them as whitespace. Left alone, text written one word per line reaches the
    /// model as a single word.
    /// </remarks>
    /// <param name="text">The input text.</param>
    /// <returns><paramref name="text"/> itself when it has none of these characters, otherwise a copy.</returns>
    public static string LineBreaksToSpaces(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        if (text.AsSpan().IndexOfAny(LineBreaks) < 0)
            return text;

        return string.Create(text.Length, text, static (destination, source) =>
        {
            source.CopyTo(destination);

            for (var index = destination.IndexOfAny(LineBreaks); index >= 0;)
            {
                destination[index] = ' ';

                var next = destination[(index + 1)..].IndexOfAny(LineBreaks);
                index = next < 0 ? -1 : index + 1 + next;
            }
        });
    }

    private static int IndexOfUnpairedSurrogate(string text, int from)
    {
        for (var i = from; i < text.Length; i++)
        {
            var c = text[i];
            if (!char.IsSurrogate(c))
                continue;

            if (char.IsHighSurrogate(c) && i + 1 < text.Length && char.IsLowSurrogate(text[i + 1]))
            {
                i++;
                continue;
            }

            return i;
        }

        return -1;
    }
}
