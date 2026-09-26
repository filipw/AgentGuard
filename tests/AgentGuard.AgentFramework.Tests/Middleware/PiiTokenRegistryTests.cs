using System.Text.Json;
using AgentGuard.AgentFramework;
using FluentAssertions;
using Microsoft.Agents.AI;
using Xunit;

namespace AgentGuard.AgentFramework.Tests.Middleware;

public class PiiTokenRegistryTests
{
    [Fact]
    public void ShouldKeepTheMostRecentTokensInOrder_WhenMoreThanTheCapacityAreRecorded()
    {
        var session = new TestSession();
        var tokens = Enumerable.Range(0, PiiTokenRegistry.Capacity + 10).Select(i => $"token-{i}").ToList();

        PiiTokenRegistry.Record(session, tokens.Take(4000));
        PiiTokenRegistry.Record(session, tokens.Skip(4000));

        PiiTokenRegistry.Read(session).Should().Equal(tokens.Skip(10));
    }

    [Fact]
    public void ShouldRecordEachTokenOnce_WhenItIsRecordedAgain()
    {
        var session = new TestSession();

        PiiTokenRegistry.Record(session, ["a", "b"]);
        PiiTokenRegistry.Record(session, ["b", "c", "c"]);

        PiiTokenRegistry.Read(session).Should().Equal("a", "b", "c");
    }

    [Fact]
    public void ShouldKeepTheTokens_WhenSessionStateIsSerializedAndRestored()
    {
        var session = new TestSession();
        PiiTokenRegistry.Record(session, ["AQtoken-1", "AQtoken-2"]);

        var serialized = session.StateBag.Serialize();
        var restored = new TestSession(AgentSessionStateBag.Deserialize(serialized));

        serialized.GetProperty(PiiTokenRegistry.StateKey).EnumerateArray().Select(t => t.GetString())
            .Should().Equal("AQtoken-1", "AQtoken-2");
        PiiTokenRegistry.Read(restored).Should().Equal("AQtoken-1", "AQtoken-2");
    }

    [Fact]
    public void ShouldNotChangeAListAlreadyRead_WhenMoreTokensAreRecorded()
    {
        var session = new TestSession();
        PiiTokenRegistry.Record(session, ["a"]);
        var read = PiiTokenRegistry.Read(session);

        PiiTokenRegistry.Record(session, ["b"]);

        read.Should().Equal("a");
        PiiTokenRegistry.Read(session).Should().Equal("a", "b");
    }

    [Fact]
    public void ShouldReadNothing_WhenThereIsNoSessionOrTheStateIsNotAList()
    {
        var session = new TestSession(AgentSessionStateBag.Deserialize(
            JsonDocument.Parse($$"""{ "{{PiiTokenRegistry.StateKey}}": { "unexpected": true } }""").RootElement));

        PiiTokenRegistry.Read(null).Should().BeEmpty();
        PiiTokenRegistry.Read(session).Should().BeEmpty();

        PiiTokenRegistry.Record(session, ["a"]);
        PiiTokenRegistry.Read(session).Should().Equal("a");
    }

    private sealed class TestSession : AgentSession
    {
        public TestSession()
        {
        }

        public TestSession(AgentSessionStateBag stateBag)
            : base(stateBag)
        {
        }
    }
}
