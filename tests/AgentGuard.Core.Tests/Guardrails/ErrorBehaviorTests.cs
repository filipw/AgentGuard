using System.Collections.Concurrent;
using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Guardrails;
using AgentGuard.Core.Streaming;
using FluentAssertions;
using Microsoft.Extensions.Logging;
using Xunit;

namespace AgentGuard.Core.Tests.Guardrails;

public class ErrorBehaviorTests
{
    private static GuardrailContext Ctx(string text, GuardrailPhase phase = GuardrailPhase.Input) =>
        new() { Text = text, Phase = phase };

    [Fact]
    public void ShouldPassWithoutAReason_WhenErrorBehaviorIsFailOpen()
    {
        var result = GuardrailResult.Error("classifier", ErrorBehavior.FailOpen, "timeout");

        result.IsBlocked.Should().BeFalse();
        result.IsError.Should().BeTrue();
        result.IsWarning.Should().BeFalse();
        result.Reason.Should().BeNull();
        result.Metadata.Should().ContainKey("errorDetail").WhoseValue.Should().Be("timeout");
    }

    [Fact]
    public void ShouldPassWithAReasonAndAWarning_WhenErrorBehaviorIsWarn()
    {
        var result = GuardrailResult.Error("classifier", ErrorBehavior.Warn, "timeout");

        result.IsBlocked.Should().BeFalse();
        result.IsError.Should().BeTrue();
        result.IsWarning.Should().BeTrue();
        result.Reason.Should().Contain("classifier").And.Contain("Warn");
        result.Metadata.Should().ContainKey("errorDetail").WhoseValue.Should().Be("timeout");
    }

    [Fact]
    public void ShouldBlock_WhenErrorBehaviorIsFailClosed()
    {
        var result = GuardrailResult.Error("classifier", ErrorBehavior.FailClosed, "timeout");

        result.IsBlocked.Should().BeTrue();
        result.IsError.Should().BeTrue();
        result.IsWarning.Should().BeFalse();
        result.Severity.Should().Be(GuardrailSeverity.High);
    }

    [Fact]
    public async Task ShouldListTheErrorInWarnings_WhenARuleFailsUnderWarn()
    {
        var pipeline = new GuardrailPipeline(
            new GuardrailPolicy("t", [new ErrorRule("judge", ErrorBehavior.Warn)]),
            new CapturingLogger<GuardrailPipeline>());

        var result = await pipeline.RunAsync(Ctx("hello"));

        result.IsBlocked.Should().BeFalse();
        result.FinalText.Should().Be("hello");
        result.Warnings.Should().ContainSingle().Which.RuleName.Should().Be("judge");
    }

    [Fact]
    public async Task ShouldNotListTheError_WhenARuleFailsUnderFailOpen()
    {
        var pipeline = new GuardrailPipeline(
            new GuardrailPolicy("t", [new ErrorRule("judge", ErrorBehavior.FailOpen)]),
            new CapturingLogger<GuardrailPipeline>());

        var result = await pipeline.RunAsync(Ctx("hello"));

        result.IsBlocked.Should().BeFalse();
        result.Warnings.Should().BeEmpty();
        result.AllResults.Should().ContainSingle().Which.IsError.Should().BeTrue();
    }

    [Fact]
    public async Task ShouldNotListABlock_WhenARuleFailsUnderFailClosed()
    {
        var pipeline = new GuardrailPipeline(
            new GuardrailPolicy("t", [new ErrorRule("judge", ErrorBehavior.FailClosed)]),
            new CapturingLogger<GuardrailPipeline>());

        var result = await pipeline.RunAsync(Ctx("hello"));

        result.IsBlocked.Should().BeTrue();
        result.Warnings.Should().BeEmpty();
    }

    [Fact]
    public async Task ShouldLogAtWarning_WhenARuleFailsUnderWarn()
    {
        var logger = new CapturingLogger<GuardrailPipeline>();
        var pipeline = new GuardrailPipeline(
            new GuardrailPolicy("t", [new ErrorRule("judge", ErrorBehavior.Warn)]), logger);

        await pipeline.RunAsync(Ctx("hello"));

        logger.Entries.Should().Contain(e => e.Level == LogLevel.Warning && e.Message.Contains("judge", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ShouldLogOnlyAtDebug_WhenARuleFailsUnderFailOpen()
    {
        var logger = new CapturingLogger<GuardrailPipeline>();
        var pipeline = new GuardrailPipeline(
            new GuardrailPolicy("t", [new ErrorRule("judge", ErrorBehavior.FailOpen)]), logger);

        await pipeline.RunAsync(Ctx("hello"));

        logger.Entries.Should().Contain(e => e.Level == LogLevel.Debug && e.Message.Contains("failed open", StringComparison.Ordinal));
        logger.Entries.Should().NotContain(e => e.Level >= LogLevel.Warning);
    }

    [Fact]
    public async Task ShouldLogAtWarning_WhenARulePassesWithAWarningOfItsOwn()
    {
        var logger = new CapturingLogger<GuardrailPipeline>();
        var rule = new DelegateRule("advisory", _ => GuardrailResult.Passed() with { IsWarning = true, Reason = "near the limit" });
        var pipeline = new GuardrailPipeline(new GuardrailPolicy("t", [rule]), logger);

        var result = await pipeline.RunAsync(Ctx("hello"));

        result.Warnings.Should().ContainSingle().Which.Reason.Should().Be("near the limit");
        logger.Entries.Should().Contain(e => e.Level == LogLevel.Warning && e.Message.Contains("near the limit", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ShouldLogWarnAtWarningAndFailOpenAtDebug_WhenStreaming()
    {
        var logger = new CapturingLogger<StreamingGuardrailPipeline>();
        var policy = new GuardrailPolicy("t",
        [
            new ErrorRule("loud-judge", ErrorBehavior.Warn, GuardrailPhase.Output),
            new ErrorRule("quiet-judge", ErrorBehavior.FailOpen, GuardrailPhase.Output)
        ]);
        var pipeline = new StreamingGuardrailPipeline(
            policy, new ProgressiveStreamingOptions { MinCharsBeforeFirstCheck = 0, EvaluationIntervalChars = 1 }, logger);

        await foreach (var _ in pipeline.ProcessStreamAsync(Chunks("hello"), Ctx("", GuardrailPhase.Output)))
        {
        }

        logger.Entries.Should().Contain(e => e.Level == LogLevel.Warning && e.Message.Contains("loud-judge", StringComparison.Ordinal));
        logger.Entries.Should().Contain(e => e.Level == LogLevel.Debug
            && e.Message.Contains("quiet-judge", StringComparison.Ordinal)
            && e.Message.Contains("failed open", StringComparison.Ordinal));
        logger.Entries.Should().NotContain(e => e.Level >= LogLevel.Warning && e.Message.Contains("quiet-judge", StringComparison.Ordinal));
    }

    private static async IAsyncEnumerable<string> Chunks(params string[] chunks)
    {
        foreach (var chunk in chunks)
        {
            await Task.Yield();
            yield return chunk;
        }
    }

    private sealed class ErrorRule(string name, ErrorBehavior behavior, GuardrailPhase phase = GuardrailPhase.Input) : IGuardrailRule
    {
        public string Name => name;
        public GuardrailPhase Phase => phase;

        public ValueTask<GuardrailResult> EvaluateAsync(GuardrailContext context, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(GuardrailResult.Error(name, behavior, "service unavailable"));
    }

    private sealed class DelegateRule(string name, Func<GuardrailContext, GuardrailResult> evaluate) : IGuardrailRule
    {
        public string Name => name;
        public GuardrailPhase Phase => GuardrailPhase.Input;

        public ValueTask<GuardrailResult> EvaluateAsync(GuardrailContext context, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(evaluate(context));
    }

    private sealed class CapturingLogger<T> : ILogger<T>
    {
        public ConcurrentQueue<(LogLevel Level, string Message)> Entries { get; } = new();

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
            Entries.Enqueue((logLevel, formatter(state, exception)));
    }
}
