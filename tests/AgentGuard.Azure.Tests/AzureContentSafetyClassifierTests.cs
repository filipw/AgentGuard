using AgentGuard.Azure.ContentSafety;
using AgentGuard.Core.Rules.ContentSafety;
using Azure.AI.ContentSafety;
using FluentAssertions;
using Xunit;

namespace AgentGuard.Azure.Tests;

public class AzureContentSafetyClassifierTests
{
    // Pure function tests for mapping logic — no mocking, real value

    [Theory]
    [InlineData(0, ContentSafetySeverity.Safe)]
    [InlineData(1, ContentSafetySeverity.Low)]
    [InlineData(2, ContentSafetySeverity.Low)]
    [InlineData(3, ContentSafetySeverity.Medium)]
    [InlineData(4, ContentSafetySeverity.Medium)]
    [InlineData(5, ContentSafetySeverity.High)]
    [InlineData(6, ContentSafetySeverity.High)]
    public void MapSeverity_ShouldMapAzureScaleToDiscreteLevels(int azureSeverity, ContentSafetySeverity expected)
    {
        AzureContentSafetyClassifier.MapSeverity(azureSeverity).Should().Be(expected);
    }

    [Fact]
    public void MapCategory_ShouldMapHate()
    {
        AzureContentSafetyClassifier.MapCategory(TextCategory.Hate).Should().Be(ContentSafetyCategory.Hate);
    }

    [Fact]
    public void MapCategory_ShouldMapViolence()
    {
        AzureContentSafetyClassifier.MapCategory(TextCategory.Violence).Should().Be(ContentSafetyCategory.Violence);
    }

    [Fact]
    public void MapCategory_ShouldMapSelfHarm()
    {
        AzureContentSafetyClassifier.MapCategory(TextCategory.SelfHarm).Should().Be(ContentSafetyCategory.SelfHarm);
    }

    [Fact]
    public void MapCategory_ShouldMapSexual()
    {
        AzureContentSafetyClassifier.MapCategory(TextCategory.Sexual).Should().Be(ContentSafetyCategory.Sexual);
    }

    [Fact]
    public void MapCategory_ShouldReturnNone_ForUnknownCategory()
    {
        // TextCategory is a struct that can hold arbitrary string values
        AzureContentSafetyClassifier.MapCategory(new TextCategory("UnknownCategory")).Should().Be(ContentSafetyCategory.None);
    }

    // Severity boundary tests — verify the exact Azure 0-6 scale boundaries

    [Fact]
    public void MapSeverity_NegativeValue_ShouldNotCrash()
    {
        // Defensive: Azure shouldn't return negative but verify we don't crash
        // Negative values hit the <= 2 branch, mapping to Low
        AzureContentSafetyClassifier.MapSeverity(-1).Should().Be(ContentSafetySeverity.Low);
    }

    [Fact]
    public void MapSeverity_OverMaxValue_ShouldMapToHigh()
    {
        AzureContentSafetyClassifier.MapSeverity(100).Should().Be(ContentSafetySeverity.High);
    }
}
