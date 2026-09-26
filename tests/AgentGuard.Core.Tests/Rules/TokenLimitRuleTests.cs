using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Rules.TokenLimits;
using FluentAssertions;
using Microsoft.ML.Tokenizers;
using Xunit;

namespace AgentGuard.Core.Tests.Rules;

public class TokenLimitRuleTests
{
    private static GuardrailContext Ctx(string text, GuardrailPhase phase = GuardrailPhase.Input) =>
        new() { Text = text, Phase = phase };

    [Fact]
    public async Task ShouldPass_WhenUnderLimit()
    {
        var rule = new TokenLimitRule(new TokenLimitOptions { MaxTokens = 100 });
        var result = await rule.EvaluateAsync(Ctx("Hello world"));
        result.IsBlocked.Should().BeFalse();
        result.IsModified.Should().BeFalse();
    }

    [Fact]
    public async Task ShouldPass_WhenEmptyInput()
    {
        var rule = new TokenLimitRule(new TokenLimitOptions { MaxTokens = 10 });
        var result = await rule.EvaluateAsync(Ctx(""));
        result.IsBlocked.Should().BeFalse();
    }

    [Fact]
    public async Task ShouldBlock_WhenOverLimitWithRejectStrategy()
    {
        var rule = new TokenLimitRule(new TokenLimitOptions { MaxTokens = 2, OverflowStrategy = TokenOverflowStrategy.Reject });
        var longText = string.Join(" ", Enumerable.Repeat("word", 100));
        var result = await rule.EvaluateAsync(Ctx(longText));
        result.IsBlocked.Should().BeTrue();
        result.Reason.Should().Contain("exceeds token limit");
        result.Severity.Should().Be(GuardrailSeverity.Medium);
    }

    [Fact]
    public async Task ShouldTruncate_WhenOverLimitWithTruncateStrategy()
    {
        var rule = new TokenLimitRule(new TokenLimitOptions { MaxTokens = 5, OverflowStrategy = TokenOverflowStrategy.Truncate });
        var longText = string.Join(" ", Enumerable.Repeat("word", 100));
        var result = await rule.EvaluateAsync(Ctx(longText));
        result.IsModified.Should().BeTrue();
        result.ModifiedText.Should().NotBeNull();
        result.ModifiedText!.Length.Should().BeLessThan(longText.Length);
        result.Reason.Should().Contain("truncated");
    }

    [Fact]
    public async Task ShouldWarn_WhenOverLimitWithWarnStrategy()
    {
        var rule = new TokenLimitRule(new TokenLimitOptions { MaxTokens = 2, OverflowStrategy = TokenOverflowStrategy.Warn });
        var longText = string.Join(" ", Enumerable.Repeat("word", 100));
        var result = await rule.EvaluateAsync(Ctx(longText));
        result.IsBlocked.Should().BeFalse();
        result.IsModified.Should().BeFalse();
        result.Reason.Should().Contain("Token limit exceeded");
        result.Metadata.Should().ContainKey("token_count");
        result.Metadata.Should().ContainKey("max_tokens");
    }

    [Fact]
    public void ShouldDefaultToInputPhase()
    {
        var rule = new TokenLimitRule();
        rule.Phase.Should().Be(GuardrailPhase.Input);
    }

    [Fact]
    public void ShouldRespectOutputPhase()
    {
        var rule = new TokenLimitRule(new TokenLimitOptions { Phase = GuardrailPhase.Output });
        rule.Phase.Should().Be(GuardrailPhase.Output);
        rule.Name.Should().Contain("output");
    }

    [Fact]
    public void ShouldHaveCorrectOrder()
    {
        new TokenLimitRule().Order.Should().Be(40);
    }

    [Fact]
    public async Task ShouldPass_WhenExactlyAtLimit()
    {
        // Use a small token limit; one word is typically one token
        var rule = new TokenLimitRule(new TokenLimitOptions { MaxTokens = 1000 });
        var result = await rule.EvaluateAsync(Ctx("Hello"));
        result.IsBlocked.Should().BeFalse();
    }

    // counts come from the real tokenizer, so text in scripts that cost a token per character
    // is not undercounted

    private const string English = "Please summarize the attached quarterly report and highlight the three biggest risks for next year.";
    private const string Chinese = "请总结附件中的季度报告，并突出主要风险。我们需要在下周一之前完成这项工作。";
    private const string Japanese = "添付の四半期報告書を要約し、主なリスクを強調してください。";
    private const string Korean = "첨부된 분기 보고서를 요약하고 주요 위험을 강조해 주세요.";

    private static readonly TiktokenTokenizer Cl100k = TiktokenTokenizer.CreateForEncoding("cl100k_base");
    private static readonly TiktokenTokenizer O200k = TiktokenTokenizer.CreateForEncoding("o200k_base");

    [Fact]
    public void ShouldUseTheRealTokenizer_WhenTokenizerModelIsTheDefault()
    {
        new TokenLimitRule().UsesEstimate.Should().BeFalse("cl100k_base ships with the package");
    }

    [Theory]
    [InlineData(English)]
    [InlineData(Chinese)]
    [InlineData(Japanese)]
    [InlineData(Korean)]
    public async Task ShouldCountLikeTheRealTokenizer_WhenTextIsEnglishOrCjk(string text)
    {
        var expected = Cl100k.CountTokens(text);

        var atLimit = new TokenLimitRule(new TokenLimitOptions { MaxTokens = expected, OverflowStrategy = TokenOverflowStrategy.Warn });
        var overLimit = new TokenLimitRule(new TokenLimitOptions { MaxTokens = expected - 1, OverflowStrategy = TokenOverflowStrategy.Warn });

        (await atLimit.EvaluateAsync(Ctx(text))).Reason.Should().BeNull("the text is exactly at the limit");
        var result = await overLimit.EvaluateAsync(Ctx(text));
        result.Metadata!["token_count"].Should().Be(expected);
        result.Metadata["max_tokens"].Should().Be(expected - 1);
    }

    [Fact]
    public async Task ShouldBlock_WhenCjkTextExceedsTheBudgetAtOneTokenPerCharacter()
    {
        // the estimate this replaced counted characters / 4 and let four times the budget through
        var rule = new TokenLimitRule(new TokenLimitOptions { MaxTokens = Chinese.Length / 2 });

        var result = await rule.EvaluateAsync(Ctx(Chinese));

        result.IsBlocked.Should().BeTrue();
    }

    [Theory]
    [InlineData("o200k_base")]
    [InlineData("O200K_BASE")]
    [InlineData("gpt-4o")]
    [InlineData("gpt-4.1-mini")]
    public async Task ShouldUseTheO200kEncoding_WhenTokenizerModelNamesItOrAModelThatUsesIt(string tokenizerModel)
    {
        var expected = O200k.CountTokens(Chinese);
        expected.Should().NotBe(Cl100k.CountTokens(Chinese), "the two encodings must be told apart");

        var rule = new TokenLimitRule(new TokenLimitOptions
        {
            MaxTokens = expected - 1,
            OverflowStrategy = TokenOverflowStrategy.Warn,
            TokenizerModel = tokenizerModel
        });

        rule.UsesEstimate.Should().BeFalse();
        (await rule.EvaluateAsync(Ctx(Chinese))).Metadata!["token_count"].Should().Be(expected);
    }

    [Theory]
    [InlineData("gpt-4")]
    [InlineData("gpt-3.5-turbo")]
    [InlineData("text-embedding-3-small")]
    public async Task ShouldUseTheCl100kEncoding_WhenTokenizerModelIsAModelThatUsesIt(string tokenizerModel)
    {
        var expected = Cl100k.CountTokens(Chinese);
        var rule = new TokenLimitRule(new TokenLimitOptions
        {
            MaxTokens = expected - 1,
            OverflowStrategy = TokenOverflowStrategy.Warn,
            TokenizerModel = tokenizerModel
        });

        (await rule.EvaluateAsync(Ctx(Chinese))).Metadata!["token_count"].Should().Be(expected);
    }

    [Theory]
    [InlineData("cl200k_base")]
    [InlineData("not-a-model")]
    [InlineData("")]
    [InlineData("  ")]
    public void ShouldThrow_WhenTokenizerModelIsUnknown(string tokenizerModel)
    {
        var act = () => new TokenLimitRule(new TokenLimitOptions { TokenizerModel = tokenizerModel });

        act.Should().Throw<ArgumentException>().Which.ParamName.Should().Be("options");
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void ShouldThrow_WhenMaxTokensIsNotPositive(int maxTokens)
    {
        var act = () => new TokenLimitRule(new TokenLimitOptions { MaxTokens = maxTokens });

        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Fact]
    public async Task ShouldBlockWithTheRealCounts_WhenRejecting()
    {
        var count = Cl100k.CountTokens(Japanese);
        var rule = new TokenLimitRule(new TokenLimitOptions { MaxTokens = count - 1 });

        var result = await rule.EvaluateAsync(Ctx(Japanese));

        result.IsBlocked.Should().BeTrue();
        result.Reason.Should().Be($"Text exceeds token limit ({count} > {count - 1}).");
    }

    [Theory]
    [InlineData(English, 1)]
    [InlineData(English, 7)]
    [InlineData(Chinese, 1)]
    [InlineData(Chinese, 5)]
    [InlineData(Chinese, 20)]
    [InlineData(Japanese, 9)]
    [InlineData(Korean, 11)]
    public async Task ShouldCutOnACharacterBoundaryWithinTheBudget_WhenTruncating(string text, int maxTokens)
    {
        var rule = new TokenLimitRule(new TokenLimitOptions { MaxTokens = maxTokens, OverflowStrategy = TokenOverflowStrategy.Truncate });

        var result = await rule.EvaluateAsync(Ctx(text));

        result.IsModified.Should().BeTrue();
        var truncated = result.ModifiedText!;
        text.Should().StartWith(truncated);
        truncated.Should().NotBeEmpty();
        truncated.Should().NotContain("\uFFFD");
        var kept = Cl100k.CountTokens(truncated);
        kept.Should().BeLessThanOrEqualTo(maxTokens);
        result.Reason.Should().Be($"Text truncated from {Cl100k.CountTokens(text)} to {kept} tokens.");
    }

    [Fact]
    public async Task ShouldNotSplitSurrogatePairs_WhenTruncatingEmoji()
    {
        var text = string.Concat(Enumerable.Repeat("😀🎉", 20));
        var rule = new TokenLimitRule(new TokenLimitOptions { MaxTokens = 5, OverflowStrategy = TokenOverflowStrategy.Truncate });

        var truncated = (await rule.EvaluateAsync(Ctx(text))).ModifiedText!;

        char.IsHighSurrogate(truncated[^1]).Should().BeFalse();
        Cl100k.CountTokens(truncated).Should().BeLessThanOrEqualTo(5);
    }

    // encodings whose vocabulary package is not deployed fall back to a script-aware estimate

    [Fact]
    public async Task ShouldFallBackToTheEstimate_WhenTheEncodingDataIsNotDeployed()
    {
        var rule = new TokenLimitRule(new TokenLimitOptions
        {
            MaxTokens = Chinese.Length - 1,
            OverflowStrategy = TokenOverflowStrategy.Warn,
            TokenizerModel = "p50k_base"
        });

        rule.UsesEstimate.Should().BeTrue();
        (await rule.EvaluateAsync(Ctx(Chinese))).Metadata!["token_count"].Should().Be(TokenLimitRule.EstimateTokens(Chinese));
    }

    [Theory]
    [InlineData("abcdefgh", 2)]
    [InlineData("abcdefghi", 3)]
    [InlineData("请总结附件", 5)]
    [InlineData("こんにちは", 5)]
    [InlineData("カタカナ", 4)]
    [InlineData("안녕하세요", 5)]
    [InlineData("ｉｇｎｏｒｅ", 6)]
    [InlineData("😀😀", 2)]
    [InlineData("Привет", 3)]
    [InlineData("summary: 总结", 5)]
    public void EstimateTokens_ShouldCountCjkHangulAndKanaAsATokenEach(string text, int expected)
    {
        TokenLimitRule.EstimateTokens(text).Should().Be(expected);
    }

    [Fact]
    public void EstimateTokens_ShouldStayCloseToTheTokenizer_WhenTextIsCjk()
    {
        TokenLimitRule.EstimateTokens(Chinese).Should().BeGreaterThanOrEqualTo(Cl100k.CountTokens(Chinese) * 3 / 4);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(4)]
    [InlineData(10)]
    public async Task ShouldTruncateWithinTheEstimatedBudget_WhenUsingTheEstimate(int maxTokens)
    {
        var text = English + " " + Chinese;
        var rule = new TokenLimitRule(new TokenLimitOptions
        {
            MaxTokens = maxTokens,
            OverflowStrategy = TokenOverflowStrategy.Truncate,
            TokenizerModel = "r50k_base"
        });

        var result = await rule.EvaluateAsync(Ctx(text));

        text.Should().StartWith(result.ModifiedText!);
        TokenLimitRule.EstimateTokens(result.ModifiedText!).Should().BeLessThanOrEqualTo(maxTokens);
        TokenLimitRule.EstimateTokens(text[..(result.ModifiedText!.Length + 1)]).Should().BeGreaterThan(maxTokens,
            "the cut keeps as much text as the budget allows");
    }

    [Fact]
    public async Task ShouldRejectAndWarnWithTheEstimate_WhenUsingTheEstimate()
    {
        var estimate = TokenLimitRule.EstimateTokens(Korean);
        var reject = new TokenLimitRule(new TokenLimitOptions { MaxTokens = estimate - 1, TokenizerModel = "p50k_edit" });
        var warn = new TokenLimitRule(new TokenLimitOptions
        {
            MaxTokens = estimate - 1,
            OverflowStrategy = TokenOverflowStrategy.Warn,
            TokenizerModel = "p50k_edit"
        });
        var pass = new TokenLimitRule(new TokenLimitOptions { MaxTokens = estimate, TokenizerModel = "p50k_edit" });

        (await reject.EvaluateAsync(Ctx(Korean))).IsBlocked.Should().BeTrue();
        var warned = await warn.EvaluateAsync(Ctx(Korean));
        warned.IsBlocked.Should().BeFalse();
        warned.Metadata!["token_count"].Should().Be(estimate);
        (await pass.EvaluateAsync(Ctx(Korean))).IsBlocked.Should().BeFalse();
    }
}
