using System.Text;

namespace AgentGuard.Onnx.Tests;

/// <summary>
/// Model-free building blocks for windowing tests: a word-based token counter (one token per
/// whitespace-separated word) and text builders, so windowing can be verified without a tokenizer.
/// </summary>
internal static class WindowingTestHelpers
{
    /// <summary>Counts whitespace-separated words - one "token" per word.</summary>
    public static int CountWords(ReadOnlySpan<char> text)
    {
        var count = 0;
        var inWord = false;
        foreach (var c in text)
        {
            if (char.IsWhiteSpace(c))
            {
                inWord = false;
            }
            else if (!inWord)
            {
                inWord = true;
                count++;
            }
        }

        return count;
    }

    /// <summary>Counts every non-whitespace character as one token.</summary>
    public static int CountNonWhitespaceChars(ReadOnlySpan<char> text)
    {
        var count = 0;
        foreach (var c in text)
        {
            if (!char.IsWhiteSpace(c))
                count++;
        }

        return count;
    }

    /// <summary>Builds <c>w0 w1 ... w{count-1}</c>, a text of <paramref name="count"/> distinct one-token words.</summary>
    public static string Words(int count, string prefix = "w")
    {
        var builder = new StringBuilder();
        for (var i = 0; i < count; i++)
        {
            if (i > 0)
                builder.Append(' ');
            builder.Append(prefix).Append(i);
        }

        return builder.ToString();
    }

    /// <summary>Builds a text of <paramref name="count"/> filler words with <paramref name="marker"/> replacing the word at <paramref name="index"/>.</summary>
    public static string WordsWithMarker(int count, int index, string marker)
    {
        var words = Words(count).Split(' ');
        words[index] = marker;
        return string.Join(' ', words);
    }

    /// <summary>A classifier stand-in that fails the test if the model would have been called.</summary>
    public static T NotCalled<T>(string text) =>
        throw new InvalidOperationException($"the classifier must not be called (text: '{text}')");
}
