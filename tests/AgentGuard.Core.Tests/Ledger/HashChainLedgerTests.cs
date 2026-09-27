using System.Globalization;
using System.Reflection;
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
    public void ShouldDetectTamper_WhenRawCapturedInputMutated()
    {
        var ledger = new HashChainLedger();
        ledger.Append(Decision() with { Input = "original", Output = "original" });

        // raw captured content is bound into the chain, so mutating it alone is detected
        var field = typeof(HashChainLedger).GetField("_entries",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!;
        var list = (System.Collections.IList)field.GetValue(ledger)!;
        var original = (GuardrailLedgerEntry)list[0]!;
        list[0] = original with { Decision = original.Decision with { Input = "tampered" } };

        ledger.Verify(out var brokenAtSeq).Should().BeFalse();
        brokenAtSeq.Should().Be(0);
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

    [Fact]
    public void ShouldCreateDirectory_WhenMissing()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"agentguard-ledger-{Guid.NewGuid():N}");
        var path = Path.Combine(dir, "ledger.jsonl");
        try
        {
            Directory.Exists(dir).Should().BeFalse();

            var ledger = new HashChainLedger(path);
            Directory.Exists(dir).Should().BeTrue();

            ledger.Append(Decision());
            File.ReadAllLines(path).Should().HaveCount(1);
        }
        finally
        {
            if (Directory.Exists(dir)) Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void ShouldLoadAndVerify_PersistedChain()
    {
        var path = Path.Combine(Path.GetTempPath(), $"agentguard-ledger-{Guid.NewGuid():N}.jsonl");
        try
        {
            var ledger = new HashChainLedger(path);
            ledger.Append(Decision("passed", "a"));
            ledger.Append(Decision("blocked", "b"));
            ledger.Append(Decision("modified", "c"));

            var loaded = HashChainLedger.Load(path);

            loaded.Count.Should().Be(3);
            loaded.Verify().Should().BeTrue();
            loaded.Entries.Select(e => e.Seq).Should().ContainInOrder(0L, 1L, 2L);
            loaded.Entries[1].Decision.Outcome.Should().Be("blocked");
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }

    [Fact]
    public void ShouldDetectTamper_OnLoadedChain_WhenPersistedLineMutated()
    {
        var path = Path.Combine(Path.GetTempPath(), $"agentguard-ledger-{Guid.NewGuid():N}.jsonl");
        try
        {
            var ledger = new HashChainLedger(path);
            ledger.Append(Decision("passed"));
            ledger.Append(Decision("passed"));
            ledger.Append(Decision("passed"));

            // tamper a persisted line on disk
            var lines = File.ReadAllLines(path);
            lines[1] = lines[1].Replace("\"outcome\":\"passed\"", "\"outcome\":\"blocked\"");
            File.WriteAllLines(path, lines);

            var loaded = HashChainLedger.Load(path);
            loaded.Verify(out var brokenAtSeq).Should().BeFalse();
            brokenAtSeq.Should().Be(1);
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }

    [Fact]
    public void ShouldDetectTamper_WhenFieldsRebalancedAcrossDelimiter()
    {
        // a naive "|"-joined serialization lets two different decisions collide
        // (agent "x" + outcome "y|z" vs agent "x|y" + outcome "z"); the length-prefixed
        // canonical form must keep them distinct so the tamper is detected
        var ledger = new HashChainLedger();
        ledger.Append(Decision("y|z") with { AgentName = "x" });

        var field = typeof(HashChainLedger).GetField("_entries",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!;
        var list = (System.Collections.IList)field.GetValue(ledger)!;
        var original = (GuardrailLedgerEntry)list[0]!;
        list[0] = original with { Decision = original.Decision with { AgentName = "x|y", Outcome = "z" } };

        ledger.Verify(out var brokenAtSeq).Should().BeFalse();
        brokenAtSeq.Should().Be(0);
    }

    [Fact]
    public void ShouldPersistInChainOrder_WhenAppendedConcurrentlyToFile()
    {
        var path = Path.Combine(Path.GetTempPath(), $"agentguard-ledger-{Guid.NewGuid():N}.jsonl");
        try
        {
            var ledger = new HashChainLedger(path);

            Parallel.For(0, 200, _ => ledger.Append(Decision()));

            // the persisted JSONL order must match the chain order, so a reload verifies
            var loaded = HashChainLedger.Load(path);
            loaded.Count.Should().Be(200);
            loaded.Verify().Should().BeTrue();
            loaded.Entries.Select(e => e.Seq).Should().BeInAscendingOrder().And.OnlyHaveUniqueItems();
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }

    [Fact]
    public void ShouldResumeWriting_WhenLoadedWithResumeWriting()
    {
        var path = Path.Combine(Path.GetTempPath(), $"agentguard-ledger-{Guid.NewGuid():N}.jsonl");
        try
        {
            var ledger = new HashChainLedger(path);
            ledger.Append(Decision("passed", "a"));
            ledger.Append(Decision("passed", "b"));

            var resumed = HashChainLedger.Load(path, resumeWriting: true);
            resumed.Append(Decision("blocked", "c"));

            resumed.Count.Should().Be(3);
            resumed.Verify().Should().BeTrue();
            File.ReadAllLines(path).Should().HaveCount(3);

            // reload the extended chain from disk and re-verify
            var reloaded = HashChainLedger.Load(path);
            reloaded.Count.Should().Be(3);
            reloaded.Verify().Should().BeTrue();
            reloaded.Entries[2].Decision.Outcome.Should().Be("blocked");
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }

    private static string TempLedgerPath() =>
        Path.Combine(Path.GetTempPath(), $"agentguard-ledger-{Guid.NewGuid():N}.jsonl");

    [Fact]
    public void ShouldContinueThePersistedChain_WhenReopenedOnAnExistingFile()
    {
        var path = TempLedgerPath();
        try
        {
            string lastPersistedHash;
            using (var first = new HashChainLedger(path))
            {
                first.Append(Decision("passed", "a"));
                first.Append(Decision("blocked", "b"));
                lastPersistedHash = first.Entries[^1].Hash;
            }

            // a process restart: a new ledger over the same file
            using (var second = new HashChainLedger(path))
            {
                second.Append(Decision("modified", "c"));
                second.Append(Decision("passed", "d"));

                second.Entries.Select(e => e.Seq).Should().Equal(2L, 3L);
                second.Entries[0].PreviousHash.Should().Be(lastPersistedHash);
                second.Verify().Should().BeTrue();
            }

            var loaded = HashChainLedger.Load(path);
            loaded.Entries.Select(e => e.Seq).Should().Equal(0L, 1L, 2L, 3L);
            loaded.Verify(out var brokenAtSeq).Should().BeTrue();
            brokenAtSeq.Should().Be(-1);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void ShouldKeepOneChain_WhenResumedThroughLoadAndThenReopened()
    {
        var path = TempLedgerPath();
        try
        {
            using (var ledger = new HashChainLedger(path))
                ledger.Append(Decision("passed", "a"));

            using (var resumed = HashChainLedger.Load(path, resumeWriting: true))
                resumed.Append(Decision("passed", "b"));

            using (var reopened = new HashChainLedger(path))
                reopened.Append(Decision("passed", "c"));

            var loaded = HashChainLedger.Load(path);
            loaded.Entries.Select(e => e.Seq).Should().Equal(0L, 1L, 2L);
            loaded.Verify().Should().BeTrue();
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void ShouldThrowInvalidDataException_WhenTheLastLineIsAnIncompleteWrite()
    {
        var path = TempLedgerPath();
        try
        {
            using (var ledger = new HashChainLedger(path))
                ledger.Append(Decision());
            File.AppendAllText(path, "{\"seq\":1,\"previousHash\":\"ab");
            var before = File.ReadAllText(path);

            var act = () => new HashChainLedger(path);

            act.Should().Throw<InvalidDataException>().WithMessage($"*{path}*");
            File.ReadAllText(path).Should().Be(before, "a ledger that cannot continue the chain must not write to the file");
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void ShouldThrowInvalidDataException_WhenTheLastEntryNoLongerMatchesItsHash()
    {
        var path = TempLedgerPath();
        try
        {
            using (var ledger = new HashChainLedger(path))
            {
                ledger.Append(Decision("passed"));
                ledger.Append(Decision("passed"));
            }

            var lines = File.ReadAllLines(path);
            lines[^1] = lines[^1].Replace("\"outcome\":\"passed\"", "\"outcome\":\"blocked\"", StringComparison.Ordinal);
            File.WriteAllLines(path, lines);

            var act = () => new HashChainLedger(path);

            act.Should().Throw<InvalidDataException>().WithMessage($"*{path}*");
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Theory]
    [InlineData("")]
    [InlineData("\n\r\n  \n")]
    public void ShouldStartAtGenesis_WhenTheFileHoldsNoEntries(string content)
    {
        var path = TempLedgerPath();
        try
        {
            File.WriteAllText(path, content);

            using (var ledger = new HashChainLedger(path))
            {
                ledger.Append(Decision());

                ledger.Entries[0].Seq.Should().Be(0);
                ledger.Entries[0].PreviousHash.Should().BeEmpty();
            }

            var loaded = HashChainLedger.Load(path);
            loaded.Count.Should().Be(1);
            loaded.Verify().Should().BeTrue();
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void ShouldKeepEntriesOnSeparateLines_WhenTheLastLineHasNoLineBreak()
    {
        var path = TempLedgerPath();
        try
        {
            using (var first = new HashChainLedger(path))
                first.Append(Decision("passed", "a"));
            File.WriteAllText(path, File.ReadAllText(path).TrimEnd());

            using (var second = new HashChainLedger(path))
                second.Append(Decision("passed", "b"));

            var loaded = HashChainLedger.Load(path);
            loaded.Entries.Select(e => e.Seq).Should().Equal(0L, 1L);
            loaded.Verify().Should().BeTrue();
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void ShouldCheckThatTheEntriesLinkToThePersistedTail_WhenVerifyingAContinuedChain()
    {
        var path = TempLedgerPath();
        try
        {
            using (var first = new HashChainLedger(path))
                first.Append(Decision());

            using var second = new HashChainLedger(path);
            second.Append(Decision());

            // the entry before the window is now a different one than the window's first entry links to
            typeof(HashChainLedger)
                .GetField("_lastTrimmedHash", BindingFlags.NonPublic | BindingFlags.Instance)!
                .SetValue(second, HashChainLedger.HashText("some other chain"));

            second.Verify(out var brokenAtSeq).Should().BeFalse();
            brokenAtSeq.Should().Be(1);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void ShouldThrowInvalidDataException_WhenALoadedLineIsNotAnEntry()
    {
        var path = TempLedgerPath();
        try
        {
            using (var ledger = new HashChainLedger(path))
                ledger.Append(Decision());
            File.AppendAllText(path, "not a ledger entry\n");

            var act = () => HashChainLedger.Load(path);

            act.Should().Throw<InvalidDataException>().WithMessage($"*{path}*line 2*");
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void ShouldProduceTheKnownHash_WhenHashingAFixedDecision()
    {
        // persisted chains are verified by recomputing this hash, so its canonical form must never drift
        var ledger = new HashChainLedger();
        ledger.Append(new GuardrailDecision
        {
            PolicyName = "golden",
            Phase = GuardrailPhase.Output,
            AgentName = "agent",
            Outcome = "blocked",
            BlockingRuleName = "rule-a",
            Severity = GuardrailSeverity.High,
            BlockReason = "reason with | delimiter",
            RuleOutcomes = [new RuleOutcome("rule-a", "blocked")],
            InputHash = HashChainLedger.HashText("in"),
            OutputHash = HashChainLedger.HashText("out"),
            Input = "raw in",
            Timestamp = new DateTimeOffset(2026, 1, 2, 3, 4, 5, TimeSpan.Zero)
        });

        ledger.Entries[0].Hash.Should().Be("610bdfba17e4e3ddfb04a405607e23ffbd499253b4455b8f525530b50b6ca82c");
    }

    [Fact]
    public void ShouldFailVerification_WhenAStageIsAddedToARecordedDecision()
    {
        var ledger = new HashChainLedger();
        ledger.Append(Decision());
        var entry = ledger.Entries[0];

        var verified = HashChainLedger.Verify([entry with { Decision = entry.Decision with { Stage = "output" } }], out _, requireGenesis: true);

        verified.Should().BeFalse("the stage is part of the hashed decision");
    }

    [Fact]
    public void ShouldKeepTheStage_WhenAChainIsExportedAndLoaded()
    {
        var path = Path.Combine(Path.GetTempPath(), $"agentguard-ledger-{Guid.NewGuid():N}.jsonl");
        try
        {
            using (var ledger = new HashChainLedger(path))
            {
                ledger.Append(Decision() with { Stage = "pre_tool_call" });
                ledger.Append(Decision());
            }

            using var loaded = HashChainLedger.Load(path);

            loaded.Entries.Select(e => e.Decision.Stage).Should().Equal("pre_tool_call", null);
            loaded.Verify().Should().BeTrue();
            File.ReadLines(path).Last().Should().NotContain("\"stage\"", "a decision without a stage doesn't write one");
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }

    [Fact]
    public void ShouldNotWriteBack_WhenLoadedWithoutResume()
    {
        var path = Path.Combine(Path.GetTempPath(), $"agentguard-ledger-{Guid.NewGuid():N}.jsonl");
        try
        {
            var ledger = new HashChainLedger(path);
            ledger.Append(Decision());

            var loaded = HashChainLedger.Load(path);
            loaded.Append(Decision());

            loaded.Count.Should().Be(2);
            File.ReadAllLines(path).Should().HaveCount(1);
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

    private sealed class ThrowingLedger : IGuardrailLedger
    {
        public void Append(GuardrailDecision decision) =>
            throw new InvalidOperationException("disk full");
    }

    [Fact]
    public async Task ShouldNotThrow_WhenLedgerAppendFails()
    {
        var rule = new TestRule("ok", GuardrailPhase.Input, _ => GuardrailResult.Passed());
        var p = new GuardrailPipeline(
            new GuardrailPolicy("t", [rule]), NullLogger<GuardrailPipeline>.Instance, new ThrowingLedger());

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

    // the in-memory chain is capped, and the JSONL mirror keeps one handle open

    private static GuardrailDecision Decision(string tag) => new()
    {
        PolicyName = "p",
        Phase = GuardrailPhase.Input,
        Outcome = "passed",
        InputHash = HashChainLedger.HashText($"in-{tag}"),
        OutputHash = HashChainLedger.HashText($"out-{tag}"),
        Timestamp = DateTimeOffset.UtcNow
    };

    [Fact]
    public void ShouldEvictOldestEntries_WhenAnInMemoryCapIsSet()
    {
        using var ledger = new HashChainLedger(maxInMemoryEntries: 3);

        for (var i = 0; i < 10; i++)
            ledger.Append(Decision(i.ToString(CultureInfo.InvariantCulture)));

        ledger.Count.Should().Be(3);
        ledger.Entries[^1].Seq.Should().Be(9, "sequence numbers keep counting the whole chain");
        ledger.Entries[0].Seq.Should().Be(7);
    }

    [Fact]
    public void ShouldVerifyTheRetainedWindow_WhenTrimmed()
    {
        using var ledger = new HashChainLedger(maxInMemoryEntries: 3);

        for (var i = 0; i < 10; i++)
            ledger.Append(Decision(i.ToString(CultureInfo.InvariantCulture)));

        ledger.Verify(out var broken).Should().BeTrue();
        broken.Should().Be(-1);
    }

    [Fact]
    public void ShouldRejectANonPositiveCap()
    {
        var act = () => new HashChainLedger(maxInMemoryEntries: 0);

        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Fact]
    public void ShouldStillPersistEveryEntry_WhenTheInMemoryChainIsCapped()
    {
        var path = Path.Combine(Path.GetTempPath(), $"ledger-{Guid.NewGuid():N}.jsonl");
        try
        {
            using (var ledger = new HashChainLedger(path, maxInMemoryEntries: 2))
            {
                for (var i = 0; i < 6; i++)
                    ledger.Append(Decision(i.ToString(CultureInfo.InvariantCulture)));

                ledger.Count.Should().Be(2);
            }

            var reloaded = HashChainLedger.Load(path);
            reloaded.Count.Should().Be(6, "the file mirror keeps the whole chain");
            reloaded.Verify().Should().BeTrue();
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void ShouldAllowReadingTheFileWhileItIsBeingWritten()
    {
        var path = Path.Combine(Path.GetTempPath(), $"ledger-{Guid.NewGuid():N}.jsonl");
        try
        {
            using var ledger = new HashChainLedger(path);
            ledger.Append(Decision("a"));

            // FileShare.Read: an auditor can tail the file without the writer having to close it
            var act = () => File.ReadAllLines(path);

            act.Should().NotThrow();
        }
        finally
        {
            File.Delete(path);
        }
    }
}
