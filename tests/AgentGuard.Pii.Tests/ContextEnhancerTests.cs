using AgentGuard.Pii.Analyzer;
using AgentGuard.Pii.Recognizers.Generic;
using FluentAssertions;
using Xunit;

namespace AgentGuard.Pii.Tests;

public class ContextEnhancerTests
{
    [Fact]
    public void ShouldBoostScore_WhenContextWordPresent()
    {
        // a bare IP scores 0.6; "ip" context should push it higher
        var engine = new AnalyzerEngine(new RecognizerRegistry([new IpRecognizer()]), defaultScoreThreshold: 0);

        var withoutContext = engine.Analyze("the value is 10.0.0.138");
        var withContext = engine.Analyze("the ip is 10.0.0.138");

        withoutContext.Should().ContainSingle();
        withContext.Should().ContainSingle();
        withContext[0].Score.Should().BeGreaterThan(withoutContext[0].Score);
    }

    [Fact]
    public void ShouldSurfaceWeakMatch_WhenContextBoostsAboveThreshold()
    {
        // a 9-digit number alone is a very weak SSN (0.05) and dropped at threshold 0.4
        var engine = new AnalyzerEngine(new RecognizerRegistry([new Recognizers.Us.UsSsnRecognizer()]), defaultScoreThreshold: 0.4);

        engine.Analyze("the number 234567890").Should().BeEmpty();
        engine.Analyze("the ssn 234567890").Should().NotBeEmpty();
    }
}
