using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Guardrails;
using AgentGuard.Core.Streaming;
using FluentAssertions;
using Xunit;

namespace AgentGuard.Core.Tests.Streaming;

public class StreamingGuardrailPipelineTests
{
    private static GuardrailContext CreateOutputContext() =>
        new() { Text = "", Phase = GuardrailPhase.Output };

    private static async IAsyncEnumerable<string> ToAsyncEnumerable(params string[] chunks)
    {
        foreach (var chunk in chunks)
        {
            await Task.Yield();
            yield return chunk;
        }
    }

    private static GuardrailPolicy CreatePolicy(params IGuardrailRule[] rules) =>
        new("test", rules);

    private static GuardrailPolicy CreatePolicyWithProgressive(
        ProgressiveStreamingOptions options, params IGuardrailRule[] rules) =>
        new("test", rules, progressiveStreaming: options);

    // ── Clean stream pass-through ────────────────────────────

    [Fact]
    public async Task ShouldYieldAllChunks_WhenNoOutputRulesExist()
    {
        var pipeline = new StreamingGuardrailPipeline(CreatePolicy());
        var chunks = ToAsyncEnumerable("Hello", " world", "!");

        var outputs = new List<StreamingPipelineOutput>();
        await foreach (var output in pipeline.ProcessStreamAsync(chunks, CreateOutputContext()))
            outputs.Add(output);

        var textOutputs = outputs.Where(o => o.Type == StreamingOutputType.TextChunk).ToList();
        textOutputs.Should().HaveCount(3);
        textOutputs[0].Text.Should().Be("Hello");
        textOutputs[1].Text.Should().Be(" world");
        textOutputs[2].Text.Should().Be("!");

        outputs.Last().Type.Should().Be(StreamingOutputType.Completed);
        outputs.Last().FinalResult!.Passed.Should().BeTrue();
    }

    [Fact]
    public async Task ShouldYieldAllChunks_WhenOutputRulesPass()
    {
        var passingRule = new TestOutputRule("pass-rule", _ => GuardrailResult.Passed());
        var policy = CreatePolicy(passingRule);
        var pipeline = new StreamingGuardrailPipeline(policy, new ProgressiveStreamingOptions
        {
            MinCharsBeforeFirstCheck = 0,
            EvaluationIntervalChars = 1
        });

        var chunks = ToAsyncEnumerable("Hello", " world");

        var outputs = new List<StreamingPipelineOutput>();
        await foreach (var output in pipeline.ProcessStreamAsync(chunks, CreateOutputContext()))
            outputs.Add(output);

        var textOutputs = outputs.Where(o => o.Type == StreamingOutputType.TextChunk).ToList();
        textOutputs.Should().HaveCount(2);
        outputs.Last().FinalResult!.Passed.Should().BeTrue();
    }

    // ── Progressive blocking ─────────────────────────────────

    [Fact]
    public async Task ShouldEmitRetractionAndReplacement_WhenRuleBlocksMidStream()
    {
        var blockingRule = new TestOutputRule("blocker", ctx =>
            ctx.Text.Contains("bad") ? GuardrailResult.Blocked("Contains bad content") : GuardrailResult.Passed());

        var policy = CreatePolicy(blockingRule);
        var pipeline = new StreamingGuardrailPipeline(policy, new ProgressiveStreamingOptions
        {
            MinCharsBeforeFirstCheck = 0,
            EvaluationIntervalChars = 1
        });

        var chunks = ToAsyncEnumerable("Hello ", "this is bad", " content");

        var outputs = new List<StreamingPipelineOutput>();
        await foreach (var output in pipeline.ProcessStreamAsync(chunks, CreateOutputContext()))
            outputs.Add(output);

        // Should have yielded text chunks before the violation was detected
        outputs.Where(o => o.Type == StreamingOutputType.TextChunk).Should().NotBeEmpty();

        // Should have retraction and replacement events
        var events = outputs.Where(o => o.Type == StreamingOutputType.GuardrailEvent).ToList();
        events.Should().HaveCount(2);
        events[0].GuardrailEvent!.Type.Should().Be(StreamingGuardrailEventType.Retraction);
        events[1].GuardrailEvent!.Type.Should().Be(StreamingGuardrailEventType.Replacement);
        events[1].GuardrailEvent!.ReplacementText.Should().Contain("bad content");

        // Should end with a blocked completion
        var completion = outputs.Last();
        completion.Type.Should().Be(StreamingOutputType.Completed);
        completion.FinalResult!.IsBlocked.Should().BeTrue();
    }

    [Fact]
    public async Task ShouldTrackAccumulatedTextLength_InRetractionEvent()
    {
        var blockingRule = new TestOutputRule("blocker", ctx =>
            ctx.Text.Contains("bad") ? GuardrailResult.Blocked("Blocked") : GuardrailResult.Passed());

        var policy = CreatePolicy(blockingRule);
        var pipeline = new StreamingGuardrailPipeline(policy, new ProgressiveStreamingOptions
        {
            MinCharsBeforeFirstCheck = 0,
            EvaluationIntervalChars = 1
        });

        var chunks = ToAsyncEnumerable("Hello", " bad");

        var outputs = new List<StreamingPipelineOutput>();
        await foreach (var output in pipeline.ProcessStreamAsync(chunks, CreateOutputContext()))
            outputs.Add(output);

        var retraction = outputs.First(o =>
            o.Type == StreamingOutputType.GuardrailEvent &&
            o.GuardrailEvent!.Type == StreamingGuardrailEventType.Retraction);

        retraction.GuardrailEvent!.AccumulatedTextLength.Should().Be(9); // "Hello" + " bad" = 9
    }

    // ── Progressive modification ─────────────────────────────

    [Fact]
    public async Task ShouldEmitRetractionAndReplacement_WhenRuleModifiesMidStream()
    {
        var redactingRule = new TestOutputRule("redactor", ctx =>
            ctx.Text.Contains("secret")
                ? GuardrailResult.Modified(ctx.Text.Replace("secret", "[REDACTED]"), "PII redacted")
                : GuardrailResult.Passed());

        var policy = CreatePolicy(redactingRule);
        var pipeline = new StreamingGuardrailPipeline(policy, new ProgressiveStreamingOptions
        {
            MinCharsBeforeFirstCheck = 0,
            EvaluationIntervalChars = 1
        });

        var chunks = ToAsyncEnumerable("My secret is hidden");

        var outputs = new List<StreamingPipelineOutput>();
        await foreach (var output in pipeline.ProcessStreamAsync(chunks, CreateOutputContext()))
            outputs.Add(output);

        var events = outputs.Where(o => o.Type == StreamingOutputType.GuardrailEvent).ToList();
        events.Should().HaveCount(2);
        events[0].GuardrailEvent!.Type.Should().Be(StreamingGuardrailEventType.Retraction);
        events[1].GuardrailEvent!.Type.Should().Be(StreamingGuardrailEventType.Replacement);
        events[1].GuardrailEvent!.ReplacementText.Should().Contain("[REDACTED]");

        outputs.Last().FinalResult!.WasModified.Should().BeTrue();
    }

    // ── Final check catches FinalOnly rules ──────────────────

    [Fact]
    public async Task ShouldRunFinalOnlyRules_AfterStreamCompletes()
    {
        var finalOnlyRule = new TestFinalOnlyOutputRule("final-blocker", ctx =>
            ctx.Text.Contains("hallucination") ? GuardrailResult.Blocked("Ungrounded") : GuardrailResult.Passed());

        var policy = CreatePolicy(finalOnlyRule);
        var pipeline = new StreamingGuardrailPipeline(policy, new ProgressiveStreamingOptions
        {
            MinCharsBeforeFirstCheck = 0,
            EvaluationIntervalChars = 1
        });

        var chunks = ToAsyncEnumerable("This is a ", "hallucination");

        var outputs = new List<StreamingPipelineOutput>();
        await foreach (var output in pipeline.ProcessStreamAsync(chunks, CreateOutputContext()))
            outputs.Add(output);

        // Text chunks should have been yielded (FinalOnly doesn't run progressively)
        outputs.Where(o => o.Type == StreamingOutputType.TextChunk).Should().HaveCount(2);

        // But final check should catch it
        var events = outputs.Where(o => o.Type == StreamingOutputType.GuardrailEvent).ToList();
        events.Should().HaveCount(2); // retraction + replacement
        events[0].GuardrailEvent!.Type.Should().Be(StreamingGuardrailEventType.Retraction);

        outputs.Last().FinalResult!.IsBlocked.Should().BeTrue();
    }

    [Fact]
    public async Task ShouldNotRunFinalOnlyRulesProgressively()
    {
        var evaluationCount = 0;
        var finalOnlyRule = new TestFinalOnlyOutputRule("final-counter", ctx =>
        {
            Interlocked.Increment(ref evaluationCount);
            return GuardrailResult.Passed();
        });

        var policy = CreatePolicy(finalOnlyRule);
        var pipeline = new StreamingGuardrailPipeline(policy, new ProgressiveStreamingOptions
        {
            MinCharsBeforeFirstCheck = 0,
            EvaluationIntervalChars = 1
        });

        // Generate many chunks to trigger multiple progressive checks
        var chunks = ToAsyncEnumerable("a", "b", "c", "d", "e", "f", "g", "h");

        await foreach (var _ in pipeline.ProcessStreamAsync(chunks, CreateOutputContext())) { }

        // FinalOnly rule should only be evaluated once (during the final check)
        evaluationCount.Should().Be(1);
    }

    // ── MinCharsBeforeFirstCheck ─────────────────────────────

    [Fact]
    public async Task ShouldRespectMinCharsBeforeFirstCheck()
    {
        var evaluationCount = 0;
        var rule = new TestOutputRule("counter", ctx =>
        {
            Interlocked.Increment(ref evaluationCount);
            return GuardrailResult.Passed();
        });

        var policy = CreatePolicy(rule);
        var pipeline = new StreamingGuardrailPipeline(policy, new ProgressiveStreamingOptions
        {
            MinCharsBeforeFirstCheck = 100,
            EvaluationIntervalChars = 1
        });

        // These chunks total < 100 chars, so no progressive check should fire
        var chunks = ToAsyncEnumerable("Hello", " world"); // 11 chars

        var outputs = new List<StreamingPipelineOutput>();
        await foreach (var output in pipeline.ProcessStreamAsync(chunks, CreateOutputContext()))
            outputs.Add(output);

        // All chunks should have been yielded
        outputs.Where(o => o.Type == StreamingOutputType.TextChunk).Should().HaveCount(2);

        // Rule should only run during final check (1 time), not progressively
        evaluationCount.Should().Be(1);
    }

    // ── EvaluationIntervalChars ──────────────────────────────

    [Fact]
    public async Task ShouldEvaluateAtConfiguredIntervals()
    {
        var evaluationCount = 0;
        var rule = new TestOutputRule("interval-counter", ctx =>
        {
            Interlocked.Increment(ref evaluationCount);
            return GuardrailResult.Passed();
        });

        var policy = CreatePolicy(rule);
        var pipeline = new StreamingGuardrailPipeline(policy, new ProgressiveStreamingOptions
        {
            MinCharsBeforeFirstCheck = 0,
            EvaluationIntervalChars = 50
        });

        // 5 chunks of 20 chars each = 100 chars total
        var chunks = ToAsyncEnumerable(
            new string('a', 20),
            new string('b', 20),
            new string('c', 20),
            new string('d', 20),
            new string('e', 20));

        await foreach (var _ in pipeline.ProcessStreamAsync(chunks, CreateOutputContext())) { }

        // Should have ~2 progressive evaluations (at 40, 80 chars) + 1 final = 3 total
        // The exact count depends on evaluation timing, but should be between 2 and 4
        evaluationCount.Should().BeGreaterThanOrEqualTo(2);
        evaluationCount.Should().BeLessThanOrEqualTo(4);
    }

    // ── Empty stream ─────────────────────────────────────────

    [Fact]
    public async Task ShouldHandleEmptyStream()
    {
        var rule = new TestOutputRule("rule", _ => GuardrailResult.Blocked("Should not run"));
        var policy = CreatePolicy(rule);
        var pipeline = new StreamingGuardrailPipeline(policy);

        var chunks = ToAsyncEnumerable();

        var outputs = new List<StreamingPipelineOutput>();
        await foreach (var output in pipeline.ProcessStreamAsync(chunks, CreateOutputContext()))
            outputs.Add(output);

        outputs.Should().HaveCount(1);
        outputs[0].Type.Should().Be(StreamingOutputType.Completed);
        outputs[0].FinalResult!.Passed.Should().BeTrue();
    }

    [Fact]
    public async Task ShouldSkipEmptyChunks()
    {
        var pipeline = new StreamingGuardrailPipeline(CreatePolicy());
        var chunks = ToAsyncEnumerable("Hello", "", " world", "");

        var outputs = new List<StreamingPipelineOutput>();
        await foreach (var output in pipeline.ProcessStreamAsync(chunks, CreateOutputContext()))
            outputs.Add(output);

        var textOutputs = outputs.Where(o => o.Type == StreamingOutputType.TextChunk).ToList();
        textOutputs.Should().HaveCount(2);
        textOutputs[0].Text.Should().Be("Hello");
        textOutputs[1].Text.Should().Be(" world");
    }

    // ── RunFinalCheck = false ────────────────────────────────

    [Fact]
    public async Task ShouldSkipFinalCheck_WhenDisabled()
    {
        var finalOnlyRule = new TestFinalOnlyOutputRule("final-blocker",
            _ => GuardrailResult.Blocked("Would block at final"));

        var policy = CreatePolicy(finalOnlyRule);
        var pipeline = new StreamingGuardrailPipeline(policy, new ProgressiveStreamingOptions
        {
            RunFinalCheck = false
        });

        var chunks = ToAsyncEnumerable("Hello world");

        var outputs = new List<StreamingPipelineOutput>();
        await foreach (var output in pipeline.ProcessStreamAsync(chunks, CreateOutputContext()))
            outputs.Add(output);

        // Should pass since final check is disabled
        outputs.Last().FinalResult!.Passed.Should().BeTrue();
    }

    // ── Violation handler integration ────────────────────────

    [Fact]
    public async Task ShouldUseViolationHandler_ForReplacementText()
    {
        var blockingRule = new TestOutputRule("blocker",
            ctx => ctx.Text.Contains("bad") ? GuardrailResult.Blocked("Bad!") : GuardrailResult.Passed());

        var handler = new MessageViolationHandler("Custom violation message");
        var policy = new GuardrailPolicy("test", [blockingRule], handler);
        var pipeline = new StreamingGuardrailPipeline(policy, new ProgressiveStreamingOptions
        {
            MinCharsBeforeFirstCheck = 0,
            EvaluationIntervalChars = 1
        });

        var chunks = ToAsyncEnumerable("This is bad");

        var outputs = new List<StreamingPipelineOutput>();
        await foreach (var output in pipeline.ProcessStreamAsync(chunks, CreateOutputContext()))
            outputs.Add(output);

        var replacement = outputs.First(o =>
            o.Type == StreamingOutputType.GuardrailEvent &&
            o.GuardrailEvent!.Type == StreamingGuardrailEventType.Replacement);

        replacement.GuardrailEvent!.ReplacementText.Should().Be("Custom violation message");
    }

    // ── Cancellation ─────────────────────────────────────────

    [Fact]
    public async Task ShouldRespectCancellation()
    {
        var cts = new CancellationTokenSource();
        var pipeline = new StreamingGuardrailPipeline(CreatePolicy());

        async IAsyncEnumerable<string> InfiniteStream(
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct = default)
        {
            var i = 0;
            while (true)
            {
                ct.ThrowIfCancellationRequested();
                await Task.Yield();
                yield return $"chunk{i++}";
                if (i == 3) cts.Cancel();
            }
        }

        var outputs = new List<StreamingPipelineOutput>();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
        {
            await foreach (var output in pipeline.ProcessStreamAsync(InfiniteStream(cts.Token), CreateOutputContext(), cancellationToken: cts.Token))
                outputs.Add(output);
        });

        outputs.Where(o => o.Type == StreamingOutputType.TextChunk).Should().HaveCountLessThan(10);
    }

    // ── Input-only rules are ignored ─────────────────────────

    [Fact]
    public async Task ShouldIgnoreInputOnlyRules()
    {
        var inputRule = new TestRule("input-rule", GuardrailPhase.Input,
            _ => GuardrailResult.Blocked("Should not block streaming output"));

        var policy = CreatePolicy(inputRule);
        var pipeline = new StreamingGuardrailPipeline(policy, new ProgressiveStreamingOptions
        {
            MinCharsBeforeFirstCheck = 0,
            EvaluationIntervalChars = 1
        });

        var chunks = ToAsyncEnumerable("Hello world");

        var outputs = new List<StreamingPipelineOutput>();
        await foreach (var output in pipeline.ProcessStreamAsync(chunks, CreateOutputContext()))
            outputs.Add(output);

        outputs.Last().FinalResult!.Passed.Should().BeTrue();
    }

    // ── Adaptive rules ───────────────────────────────────────

    [Fact]
    public async Task ShouldEvaluateAdaptiveRules_AtLargerIntervals()
    {
        var adaptiveCount = 0;
        var everyCheckCount = 0;

        var everyCheckRule = new TestOutputRule("every-check", ctx =>
        {
            Interlocked.Increment(ref everyCheckCount);
            return GuardrailResult.Passed();
        });

        var adaptiveRule = new TestAdaptiveOutputRule("adaptive", ctx =>
        {
            Interlocked.Increment(ref adaptiveCount);
            return GuardrailResult.Passed();
        });

        var policy = CreatePolicy(everyCheckRule, adaptiveRule);
        var pipeline = new StreamingGuardrailPipeline(policy, new ProgressiveStreamingOptions
        {
            MinCharsBeforeFirstCheck = 0,
            EvaluationIntervalChars = 10,
            AdaptiveRuleMinCharInterval = 100
        });

        // 10 chunks of 20 chars = 200 chars total
        var chunks = Enumerable.Range(0, 10).Select(_ => new string('x', 20)).ToArray();

        await foreach (var _ in pipeline.ProcessStreamAsync(ToAsyncEnumerable(chunks), CreateOutputContext())) { }

        // EveryCheck should run more frequently than Adaptive
        everyCheckCount.Should().BeGreaterThan(adaptiveCount);
    }

    // ── Test helpers ─────────────────────────────────────────

    private sealed class TestRule(string name, GuardrailPhase phase, Func<GuardrailContext, GuardrailResult> evaluate) : IGuardrailRule
    {
        public string Name => name;
        public GuardrailPhase Phase => phase;
        public int Order => 50;

        public ValueTask<GuardrailResult> EvaluateAsync(GuardrailContext context, CancellationToken cancellationToken = default)
            => ValueTask.FromResult(evaluate(context));
    }

    private sealed class TestOutputRule(string name, Func<GuardrailContext, GuardrailResult> evaluate) : IGuardrailRule
    {
        public string Name => name;
        public GuardrailPhase Phase => GuardrailPhase.Output;
        public int Order => 50;

        public ValueTask<GuardrailResult> EvaluateAsync(GuardrailContext context, CancellationToken cancellationToken = default)
            => ValueTask.FromResult(evaluate(context));
    }

    private sealed class TestFinalOnlyOutputRule(string name, Func<GuardrailContext, GuardrailResult> evaluate) : IGuardrailRule, IStreamingGuardrailRule
    {
        public string Name => name;
        public GuardrailPhase Phase => GuardrailPhase.Output;
        public int Order => 50;
        public StreamingEvaluationMode StreamingMode => StreamingEvaluationMode.FinalOnly;

        public ValueTask<GuardrailResult> EvaluateAsync(GuardrailContext context, CancellationToken cancellationToken = default)
            => ValueTask.FromResult(evaluate(context));
    }

    private sealed class TestAdaptiveOutputRule(string name, Func<GuardrailContext, GuardrailResult> evaluate) : IGuardrailRule, IStreamingGuardrailRule
    {
        public string Name => name;
        public GuardrailPhase Phase => GuardrailPhase.Output;
        public int Order => 60;
        public StreamingEvaluationMode StreamingMode => StreamingEvaluationMode.Adaptive;

        public ValueTask<GuardrailResult> EvaluateAsync(GuardrailContext context, CancellationToken cancellationToken = default)
            => ValueTask.FromResult(evaluate(context));
    }
}
