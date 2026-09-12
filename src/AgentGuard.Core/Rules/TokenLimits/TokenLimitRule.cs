using AgentGuard.Core.Abstractions;

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
    /// <summary>Maximum token count. Default: 4000.</summary>
    public int MaxTokens { get; init; } = 4000;

    /// <summary>Which phase to enforce the limit in. Default: <see cref="GuardrailPhase.Input"/>.</summary>
    public GuardrailPhase Phase { get; init; } = GuardrailPhase.Input;

    /// <summary>What to do on overflow. Default: <see cref="TokenOverflowStrategy.Reject"/>.</summary>
    public TokenOverflowStrategy OverflowStrategy { get; init; } = TokenOverflowStrategy.Reject;

    /// <summary>
    /// Tiktoken encoding or model name used to count tokens. Default: <c>cl100k_base</c>. When it
    /// cannot be loaded the rule falls back to a characters-over-four estimate.
    /// </summary>
    public string TokenizerModel { get; init; } = "cl100k_base";
}

/// <summary>Enforces a token budget on input or output. Order 40.</summary>
public sealed class TokenLimitRule : IGuardrailRule
{
    private readonly TokenLimitOptions _options;
    private readonly Microsoft.ML.Tokenizers.Tokenizer? _tokenizer;

    /// <summary>Initializes a new instance of the <see cref="TokenLimitRule"/> class.</summary>
    /// <param name="options">Limit, phase and overflow strategy. Defaults when null.</param>
    public TokenLimitRule(TokenLimitOptions? options = null)
    {
        _options = options ?? new();
        try { _tokenizer = Microsoft.ML.Tokenizers.TiktokenTokenizer.CreateForModel(_options.TokenizerModel); }
        catch { _tokenizer = null; }
    }

    /// <inheritdoc />
    public string Name => $"token-limit-{_options.Phase.ToString().ToLowerInvariant()}";
    /// <inheritdoc />
    public GuardrailPhase Phase => _options.Phase;
    /// <inheritdoc />
    public int Order => 40;

    /// <inheritdoc />
    public ValueTask<GuardrailResult> EvaluateAsync(GuardrailContext context, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(context.Text)) return ValueTask.FromResult(GuardrailResult.Passed());
        var count = _tokenizer?.CountTokens(context.Text) ?? (int)Math.Ceiling(context.Text.Length / 4.0);
        if (count <= _options.MaxTokens) return ValueTask.FromResult(GuardrailResult.Passed());

        return ValueTask.FromResult(_options.OverflowStrategy switch
        {
            TokenOverflowStrategy.Reject => GuardrailResult.Blocked($"Text exceeds token limit ({count} > {_options.MaxTokens}).", GuardrailSeverity.Medium),
            TokenOverflowStrategy.Truncate => GuardrailResult.Modified(
                TruncateToTokens(context.Text, _options.MaxTokens), $"Text truncated from {count} to {_options.MaxTokens} tokens."),
            TokenOverflowStrategy.Warn => new() { IsBlocked = false, Reason = $"Token limit exceeded ({count} > {_options.MaxTokens}).",
                Metadata = new Dictionary<string, object> { ["token_count"] = count, ["max_tokens"] = _options.MaxTokens } },
            _ => GuardrailResult.Passed()
        });
    }

    private string TruncateToTokens(string text, int max)
    {
        if (_tokenizer is null) { var mc = max * 4; return text.Length <= mc ? text : text[..mc] + "..."; }
        var tokens = _tokenizer.EncodeToTokens(text, out _);
        if (tokens.Count <= max) return text;
        return _tokenizer.Decode(tokens.Take(max).Select(t => t.Id).ToArray()) ?? text[..(max * 4)];
    }
}
