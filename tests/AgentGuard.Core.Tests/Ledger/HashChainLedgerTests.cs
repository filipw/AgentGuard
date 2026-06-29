using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Guardrails;
using AgentGuard.Core.Ledger;
using AgentGuard.Core.Telemetry;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace AgentGuard.Core.Tests.Ledger;

public class HashChainLedgerTests
{
    private static GuardrailDecision Decision(string outcome = "passed", string text = "hello") => new()
    {
        PolicyName = "test",
        Phase = GuardrailPhase.Input,
        Outcome = outcome,
        InputHash = HashChainLedger.HashText(text),
        OutputHash = HashChainLedger.HashText(text),
        Timestamp = DateTimeOffset.UtcNow
    };

    [Fact]
    public void ShouldVerify_WhenChainIntact()
    {
        var ledger = new HashChainLedger();
        for (var i = 0; i < 10; i++)
            ledger.Append(Decision());

        ledger.Count.Should().Be(10);
        ledger.Verify().Should().BeTrue();
    }

    [Fact]
    public void ShouldVerifyEmptyChain_WhenNoEntries()
    {
        new HashChainLedger().Verify().Should().BeTrue();
    }

    [Fact]
    public void ShouldHaveMonotonicSeq_StartingAtZero()
    {
        var ledger = new HashChainLedger();
        for (var i = 0; i < 5; i++)
            ledger.Append(Decision());

        var entries = ledger.Entries;
        entries.Select(e => e.Seq).Should().ContainInOrder(0L, 1L, 2L, 3L, 4L);
    }

    [Fact]
    public void ShouldHaveEmptyPreviousHash_ForGenesisEntry()
    {
        var ledger = new HashChainLedger();
        ledger.Append(Decision());
        ledger.Append(Decision());

        var entries = ledger.Entries;
        entries[0].PreviousHash.Should().BeEmpty();
        entries[1].PreviousHash.Should().Be(entries[0].Hash);
    }

    [Fact]
    public void ShouldDetectTamper_WhenEntryMutated()
    {
        var ledger = new HashChainLedger();
        ledger.Append(Decision("passed"));
        ledger.Append(Decision("passed"));
        ledger.Append(Decision("passed"));

        // mutate a stored entry's decision outcome via reflection on the backing list
        var field = typeof(HashChainLedger).GetField("_entries",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!;
        var list = (System.Collections.IList)field.GetValue(ledger)!;
        var original = (GuardrailLedgerEntry)list[1]!;
        list[1] = original with { Decision = original.Decision with { Outcome = "blocked" } };

        ledger.Verify(out var brokenAtSeq).Should().BeFalse();
        brokenAtSeq.Should().Be(1);
    }

    [Fact]
    public void ShouldProduceVerifiableChain_WhenAppendedConcurrently()
    {
        var ledger = new HashChainLedger();

        Parallel.For(0, 500, _ => ledger.Append(Decision()));

        ledger.Count.Should().Be(500);
        ledger.Verify().Should().BeTrue();
        ledger.Entries.Select(e => e.Seq).Should().BeInAscendingOrder()
            .And.OnlyHaveUniqueItems();
    }

    [Fact]
    public void ShouldExportJsonOfChain()
    {
        var ledger = new HashChainLedger();
        ledger.Append(Decision());

        var json = ledger.Export();
        json.Should().Contain("\"seq\": 0");
        json.Should().Contain("\"hash\"");
    }

    [Fact]
    public void ShouldWriteJsonl_WhenFilePathConfigured()
    {
        var path = Path.Combine(Path.GetTempPath(), $"agentguard-ledger-{Guid.NewGuid():N}.jsonl");
        try
        {
            var ledger = new HashChainLedger(path);
            ledger.Append(Decision());
            ledger.Append(Decision());

            var lines = File.ReadAllLines(path);
            lines.Should().HaveCount(2);
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }
}

public class LedgerPipelineTests
{
    private static GuardrailContext Ctx(string text, GuardrailPhase phase = GuardrailPhase.Input) =>
        new() { Text = text, Phase = phase };

    private sealed class TestRule(string name, GuardrailPhase phase, Func<GuardrailContext, GuardrailResult> eval) : IGuardrailRule
    {
        public string Name => name;
        public GuardrailPhase Phase => phase;
        public int Order => 100;
        public ValueTask<GuardrailResult> EvaluateAsync(GuardrailContext context, CancellationToken ct = default) =>
            ValueTask.FromResult(eval(context));
    }

    [Fact]
    public async Task ShouldRecordPassedDecision()
    {
        var ledger = new HashChainLedger();
        var rule = new TestRule("ok", GuardrailPhase.Input, _ => GuardrailResult.Passed());
        var p = new GuardrailPipeline(new GuardrailPolicy("t", [rule]), NullLogger<GuardrailPipeline>.Instance, ledger);

        await p.RunAsync(Ctx("hello"));

        ledger.Entries.Should().ContainSingle();
        var d = ledger.Entries[0].Decision;
        d.Outcome.Should().Be(AgentGuardTelemetry.Outcomes.Passed);
        d.RuleOutcomes.Should().ContainSingle(r => r.RuleName == "ok" && r.Outcome == "passed");
    }

    [Fact]
    public async Task ShouldRecordBlockedDecision()
    {
        var ledger = new HashChainLedger();
        var rule = new TestRule("b", GuardrailPhase.Input, _ => GuardrailResult.Blocked("nope", GuardrailSeverity.High));
        var p = new GuardrailPipeline(new GuardrailPolicy("t", [rule]), NullLogger<GuardrailPipeline>.Instance, ledger);

        await p.RunAsync(Ctx("hello"));

        var d = ledger.Entries[0].Decision;
        d.Outcome.Should().Be(AgentGuardTelemetry.Outcomes.Blocked);
        d.BlockingRuleName.Should().Be("b");
        d.BlockReason.Should().Be("nope");
        d.Severity.Should().Be(GuardrailSeverity.High);
    }

    [Fact]
    public async Task ShouldRecordModifiedDecision()
    {
        var ledger = new HashChainLedger();
        var rule = new TestRule("m", GuardrailPhase.Input, _ => GuardrailResult.Modified("bye", "changed"));
        var p = new GuardrailPipeline(new GuardrailPolicy("t", [rule]), NullLogger<GuardrailPipeline>.Instance, ledger);

        await p.RunAsync(Ctx("hello"));

        var d = ledger.Entries[0].Decision;
        d.Outcome.Should().Be(AgentGuardTelemetry.Outcomes.Modified);
        d.WasModified.Should().BeTrue();
    }

    [Fact]
    public async Task ShouldHashOnly_WhenSensitiveDataDisabled()
    {
        var previous = AgentGuardTelemetry.EnableSensitiveData;
        try
        {
            AgentGuardTelemetry.EnableSensitiveData = false;
            var ledger = new HashChainLedger();
            var rule = new TestRule("ok", GuardrailPhase.Input, _ => GuardrailResult.Passed());
            var p = new GuardrailPipeline(new GuardrailPolicy("t", [rule]), NullLogger<GuardrailPipeline>.Instance, ledger);

            await p.RunAsync(Ctx("secret"));

            var d = ledger.Entries[0].Decision;
            d.Input.Should().BeNull();
            d.Output.Should().BeNull();
            d.InputHash.Should().Be(HashChainLedger.HashText("secret"));
        }
        finally
        {
            AgentGuardTelemetry.EnableSensitiveData = previous;
        }
    }

    [Fact]
    public async Task ShouldCaptureRawContent_WhenSensitiveDataEnabled()
    {
        var previous = AgentGuardTelemetry.EnableSensitiveData;
        try
        {
            AgentGuardTelemetry.EnableSensitiveData = true;
            var ledger = new HashChainLedger();
            var rule = new TestRule("ok", GuardrailPhase.Input, _ => GuardrailResult.Passed());
            var p = new GuardrailPipeline(new GuardrailPolicy("t", [rule]), NullLogger<GuardrailPipeline>.Instance, ledger);

            await p.RunAsync(Ctx("secret"));

            var d = ledger.Entries[0].Decision;
            d.Input.Should().Be("secret");
            d.Output.Should().Be("secret");
        }
        finally
        {
            AgentGuardTelemetry.EnableSensitiveData = previous;
        }
    }

    [Fact]
    public async Task ShouldNotThrow_WhenLedgerNotConfigured()
    {
        var rule = new TestRule("ok", GuardrailPhase.Input, _ => GuardrailResult.Passed());
        var p = new GuardrailPipeline(new GuardrailPolicy("t", [rule]), NullLogger<GuardrailPipeline>.Instance);

        var act = async () => await p.RunAsync(Ctx("hello"));
        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task ShouldKeepChainVerifiable_AcrossMultipleRuns()
    {
        var ledger = new HashChainLedger();
        var rule = new TestRule("ok", GuardrailPhase.Input, _ => GuardrailResult.Passed());
        var p = new GuardrailPipeline(new GuardrailPolicy("t", [rule]), NullLogger<GuardrailPipeline>.Instance, ledger);

        for (var i = 0; i < 5; i++)
            await p.RunAsync(Ctx($"msg {i}"));

        ledger.Count.Should().Be(5);
        ledger.Verify().Should().BeTrue();
    }
}
