using AgentGuard.Pii.Analyzer;
using AgentGuard.Pii.Analyzer.Context;
using FluentAssertions;
using Xunit;

namespace AgentGuard.Pii.Tests;

public class LemmaContextEnhancerTests
{
    private static PatternRecognizer Recognizer(params string[] context) =>
        new("TEST", patterns: [new Pattern("value", @"\bVALUE\b", 0.3)], context: context);

    private static AnalyzerEngine Engine(LemmaContextAwareEnhancer enhancer, PatternRecognizer recognizer) =>
        new(new RecognizerRegistry([recognizer]), enhancer, defaultScoreThreshold: 0);

    [Fact]
    public void ShouldBoost_WhenSurroundingWordSharesStemWithContext()
    {
        // "agreed" stems to "agre", as does the context word "agree"; raw forms differ
        var enhancer = new LemmaContextAwareEnhancer(contextMatchingMode: ContextMatchingMode.WholeWord);
        var engine = Engine(enhancer, Recognizer("agree"));

        var boosted = engine.Analyze("the agreed VALUE here");
        var plain = Engine(new LemmaContextAwareEnhancer(contextMatchingMode: ContextMatchingMode.WholeWord), Recognizer("unrelated"))
            .Analyze("the agreed VALUE here");

        boosted.Should().ContainSingle();
        boosted[0].Score.Should().BeGreaterThan(plain[0].Score);
        boosted[0].RecognitionMetadata![RecognizerResult.IsScoreEnhancedByContextKey].Should().Be(true);
    }

    [Fact]
    public void ShouldMatchSubstring_InSubstringModeOnly()
    {
        // "card" is a substring of "creditcard" but not a whole word
        var substring = Engine(new LemmaContextAwareEnhancer(contextMatchingMode: ContextMatchingMode.Substring), Recognizer("card"))
            .Analyze("my creditcard VALUE");
        var wholeWord = Engine(new LemmaContextAwareEnhancer(contextMatchingMode: ContextMatchingMode.WholeWord), Recognizer("card"))
            .Analyze("my creditcard VALUE");

        substring[0].Score.Should().BeGreaterThan(0.3);
        wholeWord[0].Score.Should().Be(0.3);
    }

    [Fact]
    public void ShouldRespectPrefixWindow_WhenContextWordIsFarFromMatch()
    {
        // bank sits three keyword tokens before the match
        var narrow = Engine(new LemmaContextAwareEnhancer(contextPrefixCount: 1), Recognizer("bank"))
            .Analyze("bank one two VALUE");
        var wide = Engine(new LemmaContextAwareEnhancer(contextPrefixCount: 5), Recognizer("bank"))
            .Analyze("bank one two VALUE");

        narrow[0].Score.Should().Be(0.3);
        wide[0].Score.Should().BeGreaterThan(0.3);
    }

    [Fact]
    public void ShouldUseSuffixWindow_WhenContextWordFollowsMatch()
    {
        var noSuffix = Engine(new LemmaContextAwareEnhancer(contextSuffixCount: 0), Recognizer("account"))
            .Analyze("VALUE account");
        var withSuffix = Engine(new LemmaContextAwareEnhancer(contextSuffixCount: 2), Recognizer("account"))
            .Analyze("VALUE account");

        noSuffix[0].Score.Should().Be(0.3);
        withSuffix[0].Score.Should().BeGreaterThan(0.3);
    }

    [Fact]
    public void ShouldNotDoubleBoost_WhenEnhancingTwice()
    {
        var enhancer = new LemmaContextAwareEnhancer();
        var recognizer = Recognizer("account");
        var results = recognizer.Analyze("VALUE", []);
        foreach (var r in results)
        {
            r.RecognitionMetadata![RecognizerResult.RecognizerIdentifierKey] = recognizer.Id;
        }

        enhancer.EnhanceUsingContext("the account VALUE", results, [recognizer]);
        var afterFirst = results[0].Score;
        enhancer.EnhanceUsingContext("the account VALUE", results, [recognizer]);

        results[0].Score.Should().Be(afterFirst);
    }

    [Fact]
    public void ShouldFoldInExternalContext_WhenProvided()
    {
        var enhancer = new LemmaContextAwareEnhancer();
        var engine = Engine(enhancer, Recognizer("account"));

        var withExternal = engine.Analyze("VALUE", context: ["account"]);
        var withoutExternal = engine.Analyze("VALUE");

        withExternal[0].Score.Should().BeGreaterThan(withoutExternal[0].Score);
    }
}
