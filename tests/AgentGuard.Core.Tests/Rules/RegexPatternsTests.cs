using System.Text.RegularExpressions;
using AgentGuard.Core.Rules;
using FluentAssertions;
using Xunit;

namespace AgentGuard.Core.Tests.Rules;

// a match timeout is wall-clock, so it also fires when the thread was stalled rather than the pattern
// slow - the JIT compiling the pattern on its first candidate, a GC pause, a host with no free
// processor. A timeout is retried so that a stall doesn't turn into a pattern that was never checked.
public class RegexPatternsTests
{
    [Fact]
    public void ShouldReturnTheResultOfTheSecondAttempt_WhenTheFirstTimesOut()
    {
        var attempts = 0;

        var finished = RegexPatterns.TryRun(
            "state",
            state => ++attempts == 1 ? throw Timeout() : state.Length,
            out var result);

        finished.Should().BeTrue("one stalled attempt is not a pattern that can't finish");
        result.Should().Be(5);
        attempts.Should().Be(2);
    }

    [Fact]
    public void ShouldGiveUp_WhenEveryAttemptTimesOut()
    {
        var attempts = 0;

        var finished = RegexPatterns.TryRun<string, int>(
            "state",
            _ =>
            {
                attempts++;
                throw Timeout();
            },
            out _);

        finished.Should().BeFalse();
        attempts.Should().Be(RegexPatterns.Attempts, "a pattern that can't finish on the input is not retried forever");
    }

    [Fact]
    public void ShouldRunOnce_WhenTheFirstAttemptFinishes()
    {
        var attempts = 0;

        RegexPatterns.TryRun("state", _ => ++attempts, out _).Should().BeTrue();

        attempts.Should().Be(1);
    }

    [Fact]
    public void ShouldLetOtherExceptionsThrough()
    {
        var run = () => RegexPatterns.TryRun<string, int>("state", _ => throw new InvalidOperationException("boom"), out _);

        run.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void ShouldReportNoVerdict_WhenThePatternCannotFinishOnTheInput()
    {
        // catastrophic backtracking: no number of attempts completes this inside the budget
        var pattern = new Regex("^(a+)+$", RegexOptions.None, TimeSpan.FromMilliseconds(20));
        var text = new string('a', 40) + "!";

        pattern.TryIsMatch(text).Should().BeNull();
        pattern.IsMatchOrFalse(text).Should().BeFalse();
        pattern.TryMatch(text, out var match).Should().BeFalse();
        match.Should().BeNull();
        pattern.TryReplace(text, _ => "x").Should().BeNull();
        pattern.ReplaceOrOriginal(text, "x").Should().Be(text);
        pattern.TryMatches(text, out var matches).Should().BeFalse();
        matches.Should().BeEmpty();
    }

    [Fact]
    public void ShouldMatchReplaceAndCollect_WhenThePatternFinishes()
    {
        var pattern = new Regex(@"\d+", RegexOptions.None, TimeSpan.FromSeconds(5));

        pattern.TryIsMatch("a1b22").Should().BeTrue();
        pattern.TryIsMatch("abc").Should().BeFalse();
        pattern.TryMatch("a1b22", out var first).Should().BeTrue();
        first!.Value.Should().Be("1");
        pattern.TryMatch("abc", out var none).Should().BeTrue();
        none.Should().BeNull();
        pattern.TryReplace("a1b22", _ => "$0").Should().Be("a$0b$0", "the replacement is taken literally");
        pattern.TryMatches("a1b22", out var all).Should().BeTrue();
        all.Select(m => m.Value).Should().Equal("1", "22");
    }

    private static RegexMatchTimeoutException Timeout() => new("input", "pattern", TimeSpan.FromMilliseconds(200));
}
