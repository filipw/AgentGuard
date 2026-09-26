using System.Text;
using AgentGuard.Core.Abstractions;
using Microsoft.ML.Tokenizers;

namespace AgentGuard.Core.Rules.TokenLimits;

/// <summary>What to do with text that exceeds the configured token budget.</summary>
public enum TokenOverflowStrategy
{
    /// <summary>Block it.</summary>
    Reject,

    /// <summary>Cut it down to the limit and continue.</summary>
    Truncate,

    /// <summary>Let it through, attaching the counts as result metadata.</summary>
    Warn
}

/// <summary>Options for <see cref="TokenLimitRule"/>.</summary>
public sealed class TokenLimitOptions
{
    /// <summary>Maximum token count. Must be greater than zero. Default: 4000.</summary>
    public int MaxTokens { get; init; } = 4000;

    /// <summary>Which phase to enforce the limit in. Default: <see cref="GuardrailPhase.Input"/>.</summary>
    public GuardrailPhase Phase { get; init; } = GuardrailPhase.Input;

    /// <summary>What to do on overflow. Default: <see cref="TokenOverflowStrategy.Reject"/>.</summary>
    public TokenOverflowStrategy OverflowStrategy { get; init; } = TokenOverflowStrategy.Reject;

    /// <summary>
    /// The tokenizer that counts tokens: a tiktoken encoding name (<c>cl100k_base</c>,
    /// <c>o200k_base</c>, <c>o200k_harmony</c>, <c>p50k_base</c>, <c>p50k_edit</c>, <c>r50k_base</c>) or
    /// an OpenAI model name that maps to one (<c>gpt-4</c>, <c>gpt-4o</c>, <c>gpt-4.1</c>, <c>o3</c> and
    /// so on). Case-insensitive. Default: <c>cl100k_base</c>.
    /// </summary>
    /// <remarks>
    /// The vocabularies for <c>cl100k_base</c> (GPT-4, GPT-3.5, the <c>text-embedding-3</c> models) and
    /// <c>o200k_base</c> (GPT-4o and later) ship with the package. A name that is neither an encoding
    /// nor a model the tokenizer library knows throws an <see cref="ArgumentException"/> when the rule
    /// is created. The older encodings need their <c>Microsoft.ML.Tokenizers.Data.*</c> package in the
    /// application; while it is missing the rule counts with an estimate instead: four ASCII
    /// characters per token, one token per CJK ideograph, Kana, Hangul or fullwidth character and per
    /// character outside the Basic Multilingual Plane (emoji and the like), and two characters per
    /// token for everything else.
    /// </remarks>
    public string TokenizerModel { get; init; } = "cl100k_base";
}

/// <summary>Enforces a token budget on input or output. Order 40.</summary>
public sealed class TokenLimitRule : IGuardrailRule
{
    // the encoding names Microsoft.ML.Tokenizers loads with CreateForEncoding; anything else is a model name
    private static readonly string[] EncodingNames =
        ["cl100k_base", "o200k_base", "o200k_harmony", "p50k_base", "p50k_edit", "r50k_base"];

    private readonly TokenLimitOptions _options;
    private readonly TiktokenTokenizer? _tokenizer;

    /// <summary>Initializes a new instance of the <see cref="TokenLimitRule"/> class.</summary>
    /// <param name="options">Limit, phase, overflow strategy and tokenizer. Defaults when null.</param>
    /// <exception cref="ArgumentOutOfRangeException"><see cref="TokenLimitOptions.MaxTokens"/> is not greater than zero.</exception>
    /// <exception cref="ArgumentException">
    /// <see cref="TokenLimitOptions.TokenizerModel"/> is not an encoding or model name the tokenizer library knows.
    /// </exception>
    public TokenLimitRule(TokenLimitOptions? options = null)
    {
        _options = options ?? new();

        if (_options.MaxTokens <= 0)
            throw new ArgumentOutOfRangeException(nameof(options), _options.MaxTokens, "MaxTokens must be greater than zero.");

        _tokenizer = LoadTokenizer(_options.TokenizerModel, nameof(options));
    }

    /// <inheritdoc />
    public string Name => $"token-limit-{_options.Phase.ToString().ToLowerInvariant()}";
    /// <inheritdoc />
    public GuardrailPhase Phase => _options.Phase;
    /// <inheritdoc />
    public int Order => 40;

    /// <summary>True when the tokenizer's data is not deployed and counts come from the estimate.</summary>
    internal bool UsesEstimate => _tokenizer is null;

    /// <inheritdoc />
    public ValueTask<GuardrailResult> EvaluateAsync(GuardrailContext context, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(context.Text)) return ValueTask.FromResult(GuardrailResult.Passed());

        var max = _options.MaxTokens;
        var count = CountTokens(context.Text);
        if (count <= max) return ValueTask.FromResult(GuardrailResult.Passed());

        return ValueTask.FromResult(_options.OverflowStrategy switch
        {
            TokenOverflowStrategy.Reject => GuardrailResult.Blocked($"Text exceeds token limit ({count} > {max}).", GuardrailSeverity.Medium),
            TokenOverflowStrategy.Truncate => Truncated(context.Text, count),
            TokenOverflowStrategy.Warn => new() { IsBlocked = false, Reason = $"Token limit exceeded ({count} > {max}).",
                Metadata = new Dictionary<string, object> { ["token_count"] = count, ["max_tokens"] = max } },
            _ => GuardrailResult.Passed()
        });
    }

    /// <summary>
    /// Loads the tokenizer for an encoding or model name, or returns <c>null</c> when the name is
    /// known but its vocabulary package is not deployed.
    /// </summary>
    private static TiktokenTokenizer? LoadTokenizer(string? name, string paramName)
    {
        if (string.IsNullOrWhiteSpace(name))
            throw new ArgumentException("TokenizerModel must name a tiktoken encoding or model.", paramName);

        try
        {
            return EncodingNames.Contains(name, StringComparer.OrdinalIgnoreCase)
                ? TiktokenTokenizer.CreateForEncoding(name)
                : TiktokenTokenizer.CreateForModel(name);
        }
        catch (InvalidOperationException)
        {
            // the name is valid, but the Microsoft.ML.Tokenizers.Data package holding its vocabulary is not deployed
            return null;
        }
        catch (NotSupportedException ex)
        {
            throw UnknownTokenizer(name, paramName, ex);
        }
        catch (ArgumentException ex)
        {
            throw UnknownTokenizer(name, paramName, ex);
        }
    }

    private static ArgumentException UnknownTokenizer(string name, string paramName, Exception inner) =>
        new($"TokenizerModel '{name}' is not a tiktoken encoding ({string.Join(", ", EncodingNames)}) or a model name the tokenizer knows.",
            paramName, inner);

    private int CountTokens(string text) => _tokenizer?.CountTokens(text) ?? EstimateTokens(text);

    private GuardrailResult Truncated(string text, int count)
    {
        var (truncated, kept) = _tokenizer is null
            ? TruncateByEstimate(text, _options.MaxTokens)
            : TruncateWithTokenizer(_tokenizer, text, _options.MaxTokens);

        return GuardrailResult.Modified(truncated, $"Text truncated from {count} to {kept} tokens.");
    }

    /// <summary>
    /// Cuts <paramref name="text"/> on a token boundary so that it holds at most
    /// <paramref name="maxTokens"/> tokens. The cut never splits a character.
    /// </summary>
    private static (string Text, int Tokens) TruncateWithTokenizer(TiktokenTokenizer tokenizer, string text, int maxTokens)
    {
        // the prefix is counted again on its own, since encoding it alone can merge differently at the
        // cut; the budget shrinks by any excess until the prefix fits
        for (var budget = maxTokens; budget > 0;)
        {
            var index = tokenizer.GetIndexByTokenCount(text, budget, out var normalized, out _);
            var prefix = (normalized ?? text)[..index];
            var tokens = tokenizer.CountTokens(prefix);
            if (tokens <= maxTokens)
                return (prefix, tokens);

            budget -= tokens - maxTokens;
        }

        return ("", 0);
    }

    /// <summary>The estimate used when the tokenizer's data is not deployed.</summary>
    internal static int EstimateTokens(string text)
    {
        var quarters = 0L;
        var index = 0;
        while (index < text.Length)
        {
            Rune.DecodeFromUtf16(text.AsSpan(index), out var rune, out var consumed);
            quarters += EstimatedQuarterTokens(rune);
            index += consumed;
        }

        return (int)((quarters + 3) / 4);
    }

    private static (string Text, int Tokens) TruncateByEstimate(string text, int maxTokens)
    {
        var budget = (long)maxTokens * 4;
        var quarters = 0L;
        var index = 0;
        while (index < text.Length)
        {
            Rune.DecodeFromUtf16(text.AsSpan(index), out var rune, out var consumed);
            var cost = EstimatedQuarterTokens(rune);
            if (quarters + cost > budget)
                break;

            quarters += cost;
            index += consumed;
        }

        return (text[..index], (int)((quarters + 3) / 4));
    }

    // tiktoken encodings spend about a token on four ASCII characters, but one on each CJK ideograph,
    // Kana or Hangul syllable and more on emoji; most other scripts land in between
    private static int EstimatedQuarterTokens(Rune rune) => rune.Value switch
    {
        < 0x80 => 1,
        >= 0x10000 => 4,
        _ when IsWideScript(rune.Value) => 4,
        _ => 2
    };

    private static bool IsWideScript(int codePoint) => codePoint is
        (>= 0x1100 and <= 0x11FF)     // Hangul Jamo
        or (>= 0x2E80 and <= 0x9FFF)  // CJK radicals and punctuation, Kana, Bopomofo, Hangul compatibility Jamo, CJK ideographs
        or (>= 0xA960 and <= 0xA97F)  // Hangul Jamo Extended-A
        or (>= 0xAC00 and <= 0xD7FF)  // Hangul syllables, Hangul Jamo Extended-B
        or (>= 0xF900 and <= 0xFAFF)  // CJK compatibility ideographs
        or (>= 0xFF00 and <= 0xFFEF); // halfwidth and fullwidth forms
}
