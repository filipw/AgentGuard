using AgentGuard.Core.Abstractions;

namespace AgentGuard.Core.Rules.TokenLimits;

public enum TokenOverflowStrategy { Reject, Truncate, Warn }

public sealed class TokenLimitOptions
{
    public int MaxTokens { get; init; } = 4000;
    public GuardrailPhase Phase { get; init; } = GuardrailPhase.Input;
    public TokenOverflowStrategy OverflowStrategy { get; init; } = TokenOverflowStrategy.Reject;
    public string TokenizerModel { get; init; } = "cl100k_base";
}

public sealed class TokenLimitRule : IGuardrailRule
{
    private readonly TokenLimitOptions _options;
    private readonly Microsoft.ML.Tokenizers.Tokenizer? _tokenizer;

    public TokenLimitRule(TokenLimitOptions? options = null)
    {
        _options = options ?? new();
        try { _tokenizer = Microsoft.ML.Tokenizers.TiktokenTokenizer.CreateForModel(_options.TokenizerModel); }
        catch { _tokenizer = null; }
    }

    public string Name => $"token-limit-{_options.Phase.ToString().ToLowerInvariant()}";
    public GuardrailPhase Phase => _options.Phase;
    public int Order => 40;

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
