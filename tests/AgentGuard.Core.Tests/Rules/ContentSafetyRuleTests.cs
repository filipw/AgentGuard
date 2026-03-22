using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Rules.ContentSafety;
using FluentAssertions;
using Moq;
using Xunit;

namespace AgentGuard.Core.Tests.Rules;

public class ContentSafetyRuleTests
{
    private static GuardrailContext Ctx(string text) => new() { Text = text, Phase = GuardrailPhase.Input };

    private static Mock<IContentSafetyClassifier> MockClassifier(
        IReadOnlyList<ContentSafetyAnalysis>? categories = null,
        IReadOnlyList<BlocklistMatchResult>? blocklistMatches = null)
    {
        var mock = new Mock<IContentSafetyClassifier>();
        mock.Setup(c => c.AnalyzeWithOptionsAsync(It.IsAny<string>(), It.IsAny<ContentSafetyOptions>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ContentSafetyResult
            {
                CategoriesAnalysis = categories ?? [],
                BlocklistMatches = blocklistMatches ?? []
            });
        return mock;
    }

    [Fact]
    public async Task ShouldPass_WhenNoClassifierConfigured()
    {
        var rule = new ContentSafetyRule();
        var result = await rule.EvaluateAsync(Ctx("anything"));
        result.IsBlocked.Should().BeFalse();
    }

    [Fact]
    public async Task ShouldPass_WhenClassifierReturnsSafe()
    {
        var mock = MockClassifier(categories:
        [
            new() { Category = ContentSafetyCategory.Violence, Severity = ContentSafetySeverity.Safe }
        ]);

        var rule = new ContentSafetyRule(classifier: mock.Object);
        var result = await rule.EvaluateAsync(Ctx("peaceful text"));
        result.IsBlocked.Should().BeFalse();
    }

    [Fact]
    public async Task ShouldBlock_WhenSeverityExceedsThreshold()
    {
        var mock = MockClassifier(categories:
        [
            new() { Category = ContentSafetyCategory.Hate, Severity = ContentSafetySeverity.High }
        ]);

        var rule = new ContentSafetyRule(new ContentSafetyOptions { MaxAllowedSeverity = ContentSafetySeverity.Low }, mock.Object);
        var result = await rule.EvaluateAsync(Ctx("hateful text"));
        result.IsBlocked.Should().BeTrue();
        result.Reason.Should().Contain("Hate");
        result.Severity.Should().Be(GuardrailSeverity.Critical);
    }

    [Fact]
    public async Task ShouldPass_WhenSeverityWithinThreshold()
    {
        var mock = MockClassifier(categories:
        [
            new() { Category = ContentSafetyCategory.Violence, Severity = ContentSafetySeverity.Low }
        ]);

        var rule = new ContentSafetyRule(new ContentSafetyOptions { MaxAllowedSeverity = ContentSafetySeverity.Medium }, mock.Object);
        var result = await rule.EvaluateAsync(Ctx("mild text"));
        result.IsBlocked.Should().BeFalse();
    }

    [Fact]
    public async Task ShouldRespectCategoryFilter()
    {
        var mock = MockClassifier(categories:
        [
            new() { Category = ContentSafetyCategory.Violence, Severity = ContentSafetySeverity.High }
        ]);

        // Only checking Hate category, not Violence
        var rule = new ContentSafetyRule(new ContentSafetyOptions
        {
            Categories = ContentSafetyCategory.Hate,
            MaxAllowedSeverity = ContentSafetySeverity.Low
        }, mock.Object);

        var result = await rule.EvaluateAsync(Ctx("violent text"));
        result.IsBlocked.Should().BeFalse();
    }

    [Fact]
    public async Task ShouldMapMediumSeverityCorrectly()
    {
        var mock = MockClassifier(categories:
        [
            new() { Category = ContentSafetyCategory.SelfHarm, Severity = ContentSafetySeverity.Medium }
        ]);

        var rule = new ContentSafetyRule(new ContentSafetyOptions { MaxAllowedSeverity = ContentSafetySeverity.Low }, mock.Object);
        var result = await rule.EvaluateAsync(Ctx("concerning text"));
        result.IsBlocked.Should().BeTrue();
        result.Severity.Should().Be(GuardrailSeverity.High);
    }

    [Fact]
    public async Task ShouldPass_WhenClassifierReturnsEmpty()
    {
        var mock = MockClassifier();

        var rule = new ContentSafetyRule(classifier: mock.Object);
        var result = await rule.EvaluateAsync(Ctx("clean text"));
        result.IsBlocked.Should().BeFalse();
    }

    [Fact]
    public void ShouldHaveCorrectPhaseAndOrder()
    {
        var rule = new ContentSafetyRule();
        rule.Phase.Should().Be(GuardrailPhase.Both);
        rule.Order.Should().Be(50);
        rule.Name.Should().Be("content-safety");
    }

    // Blocklist tests

    [Fact]
    public async Task ShouldBlock_WhenBlocklistMatches()
    {
        var mock = MockClassifier(
            categories: [new() { Category = ContentSafetyCategory.Hate, Severity = ContentSafetySeverity.Safe }],
            blocklistMatches: [new() { BlocklistName = "profanity", BlocklistItemText = "badword" }]);

        var rule = new ContentSafetyRule(new ContentSafetyOptions
        {
            BlocklistNames = ["profanity"]
        }, mock.Object);

        var result = await rule.EvaluateAsync(Ctx("text with badword"));
        result.IsBlocked.Should().BeTrue();
        result.Reason.Should().Contain("profanity");
        result.Reason.Should().Contain("badword");
        result.Metadata.Should().NotBeNull();
        result.Metadata!["blocklistName"].Should().Be("profanity");
    }

    [Fact]
    public async Task ShouldPass_WhenBlocklistHasNoMatches()
    {
        var mock = MockClassifier(
            categories: [new() { Category = ContentSafetyCategory.Hate, Severity = ContentSafetySeverity.Safe }]);

        var rule = new ContentSafetyRule(new ContentSafetyOptions
        {
            BlocklistNames = ["profanity"]
        }, mock.Object);

        var result = await rule.EvaluateAsync(Ctx("clean text"));
        result.IsBlocked.Should().BeFalse();
    }

    [Fact]
    public async Task BlocklistBlock_ShouldTakePrecedenceOverCategoryAnalysis()
    {
        var mock = MockClassifier(
            categories: [new() { Category = ContentSafetyCategory.Violence, Severity = ContentSafetySeverity.High }],
            blocklistMatches: [new() { BlocklistName = "competitors", BlocklistItemText = "AcmeCorp" }]);

        var rule = new ContentSafetyRule(new ContentSafetyOptions
        {
            BlocklistNames = ["competitors"],
            MaxAllowedSeverity = ContentSafetySeverity.Low
        }, mock.Object);

        var result = await rule.EvaluateAsync(Ctx("I use AcmeCorp products"));
        result.IsBlocked.Should().BeTrue();
        // Should be the blocklist reason, not the category reason
        result.Reason.Should().Contain("competitors");
    }

    // Backward compatibility: classifiers that only implement AnalyzeAsync still work
    // (tested via a concrete stub rather than Moq, since Moq can't invoke default interface methods)

    [Fact]
    public async Task ShouldWorkWithLegacyClassifier_ThatOnlyImplementsAnalyzeAsync()
    {
        var classifier = new LegacyClassifier([
            new() { Category = ContentSafetyCategory.Hate, Severity = ContentSafetySeverity.High }
        ]);

        var rule = new ContentSafetyRule(new ContentSafetyOptions { MaxAllowedSeverity = ContentSafetySeverity.Low }, classifier);
        var result = await rule.EvaluateAsync(Ctx("hateful text"));
        result.IsBlocked.Should().BeTrue();
        result.Reason.Should().Contain("Hate");
    }

    /// <summary>
    /// Simulates a classifier written before blocklist support was added - only implements AnalyzeAsync.
    /// The default interface method on AnalyzeWithOptionsAsync delegates to this.
    /// </summary>
    private sealed class LegacyClassifier(IReadOnlyList<ContentSafetyAnalysis> results) : IContentSafetyClassifier
    {
        public ValueTask<IReadOnlyList<ContentSafetyAnalysis>> AnalyzeAsync(string text, CancellationToken cancellationToken = default)
            => ValueTask.FromResult(results);

        // Intentionally NOT overriding AnalyzeWithOptionsAsync - uses default interface method
    }
}
