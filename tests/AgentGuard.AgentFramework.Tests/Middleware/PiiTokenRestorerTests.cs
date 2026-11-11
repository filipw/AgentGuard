using System.Runtime.CompilerServices;
using System.Text;
using AgentGuard.AgentFramework;
using FluentAssertions;
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;
using TasmanianDevil.Anonymizer.Operators;
using Xunit;

namespace AgentGuard.AgentFramework.Tests.Middleware;

// tokens minted while a run is under way - a tool result's - are restored like the request's, whether they
// are added between two updates of a stream or from several tool invocations at once
public class PiiTokenRestorerTests
{
    private static readonly byte[] KeyBytes = Encoding.UTF8.GetBytes("0123456789abcdef");

    [Fact]
    public void ShouldRestoreAToken_WhenItIsAddedAfterTheRestorerWasMade()
    {
        var restorer = new PiiTokenRestorer(KeyBytes, new Dictionary<string, string>(), []);
        var token = AesCipher.Encrypt(KeyBytes, "jane@example.com");
        var text = $"Write to {token}.";

        restorer.HasTokens.Should().BeFalse();
        restorer.Restore(text).Should().BeSameAs(text, "the token is not known yet");

        restorer.Add(new Dictionary<string, string> { [token] = "jane@example.com" });

        restorer.HasTokens.Should().BeTrue();
        restorer.Restore(text).Should().Be("Write to jane@example.com.");
    }

    [Fact]
    public void ShouldNotRestoreAnAddedToken_WhenItIsNotShapedLikeOne()
    {
        var restorer = new PiiTokenRestorer(KeyBytes, new Dictionary<string, string>(), []);

        restorer.Add(new Dictionary<string, string> { ["<EMAIL_ADDRESS>"] = "jane@example.com" });

        restorer.HasTokens.Should().BeFalse();
        restorer.Restore("Write to <EMAIL_ADDRESS>, please, whenever you find the time.").Should().NotContain("jane@example.com");
    }

    [Theory]
    [InlineData(1)]
    [InlineData(1000)]
    public async Task ShouldRestoreAToken_WhenItIsAddedWhileTheStreamRuns(int chunkSize)
    {
        var restorer = new PiiTokenRestorer(KeyBytes, new Dictionary<string, string>(), []);
        var token = AesCipher.Encrypt(KeyBytes, "jane@example.com");

        var text = new StringBuilder();
        await foreach (var update in restorer.RestoreAsync(ToolCallingStream()))
            text.Append(update.Text);

        text.ToString().Should().Be("Let me look. Write to jane@example.com.");

        // the token is minted, as by a tool, after the stream has begun
        async IAsyncEnumerable<AgentResponseUpdate> ToolCallingStream([EnumeratorCancellation] CancellationToken ct = default)
        {
            yield return new AgentResponseUpdate(ChatRole.Assistant, "Let me look. ") { MessageId = "m1" };

            await Task.Yield();
            restorer.Add(new Dictionary<string, string> { [token] = "jane@example.com" });

            foreach (var piece in $"Write to {token}.".Chunk(chunkSize))
                yield return new AgentResponseUpdate(ChatRole.Assistant, new string(piece)) { MessageId = "m2" };
        }
    }

    [Fact]
    public void ShouldRestoreEveryToken_WhenTheyAreAddedAndRestoredConcurrently()
    {
        var restorer = new PiiTokenRestorer(KeyBytes, new Dictionary<string, string>(), []);
        var values = Enumerable.Range(0, 500).Select(i => $"user{i}@example.com").ToList();
        var restoredOnItsOwn = new string[values.Count];

        // each worker adds its token and restores it at once, as concurrent tool invocations do
        Parallel.For(0, values.Count, new ParallelOptions { MaxDegreeOfParallelism = 16 }, i =>
        {
            var token = AesCipher.Encrypt(KeyBytes, values[i]);
            restorer.Add(new Dictionary<string, string> { [token] = values[i] });
            restoredOnItsOwn[i] = restorer.Restore($"<{token}>");
        });

        restoredOnItsOwn.Should().Equal(values.Select(value => $"<{value}>"));
    }
}
