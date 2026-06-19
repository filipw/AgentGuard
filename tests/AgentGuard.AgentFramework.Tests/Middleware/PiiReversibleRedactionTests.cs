using System.Runtime.CompilerServices;
using System.Text;
using AgentGuard.AgentFramework;
using FluentAssertions;
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;
using Xunit;

namespace AgentGuard.AgentFramework.Tests.Middleware;

public class PiiReversibleRedactionTests
{
    private const string Key = "0123456789abcdef"; // 128-bit

    [Fact]
    public async Task RunAsync_ShouldEncryptInput_AndDecryptOutput()
    {
        string? receivedByModel = null;
        var agent = new TestAgent(
            (messages, session, options, ct) =>
            {
                receivedByModel = messages.Last().Text;
                // a model that quotes the user's text back echoes the ciphertext token verbatim
                return Task.FromResult(new AgentResponse(new ChatMessage(ChatRole.Assistant, $"You said: {receivedByModel}")));
            },
            (messages, session, options, ct) => EmptyStream(ct))
            .AsBuilder()
            .UsePiiReversibleRedaction(Key)
            .Build(null!);

        var response = await agent.RunAsync("email me at john@example.com", null, null, CancellationToken.None);

        receivedByModel.Should().NotBeNull();
        receivedByModel!.Should().NotContain("john@example.com", "the model must only ever see ciphertext");
        response.Messages.Last().Text.Should().Contain("john@example.com", "the user sees the restored value");
    }

    [Fact]
    public async Task RunAsync_ShouldLeaveInputUnchanged_WhenNoPii()
    {
        string? receivedByModel = null;
        var agent = new TestAgent(
            (messages, session, options, ct) =>
            {
                receivedByModel = messages.Last().Text;
                return Task.FromResult(new AgentResponse(new ChatMessage(ChatRole.Assistant, "ok")));
            },
            (messages, session, options, ct) => EmptyStream(ct))
            .AsBuilder()
            .UsePiiReversibleRedaction(Key)
            .Build(null!);

        await agent.RunAsync("what is the weather today", null, null, CancellationToken.None);

        receivedByModel.Should().Be("what is the weather today");
    }

    [Fact]
    public void UsePiiReversibleRedaction_ShouldThrow_OnInvalidKey()
    {
        var builder = new TestAgent(
            (m, s, o, ct) => Task.FromResult(new AgentResponse(new ChatMessage(ChatRole.Assistant, ""))),
            (m, s, o, ct) => EmptyStream(ct))
            .AsBuilder();

        var act = () => builder.UsePiiReversibleRedaction("too-short-key");

        act.Should().Throw<ArgumentException>().WithMessage("*key*");
    }

    [Fact]
    public async Task RunStreamingAsync_ShouldRestore_BestEffort()
    {
        var agent = new TestAgent(
            (m, s, o, ct) => Task.FromResult(new AgentResponse(new ChatMessage(ChatRole.Assistant, ""))),
            // emit the (encrypted) prompt as a single chunk so the token is not split across updates
            (messages, session, options, ct) => EchoStream(messages.Last().Text, ct))
            .AsBuilder()
            .UsePiiReversibleRedaction(Key)
            .Build(null!);

        var sb = new StringBuilder();
        await foreach (var update in agent.RunStreamingAsync("email me at john@example.com", null, null, CancellationToken.None))
            sb.Append(update.Text);

        sb.ToString().Should().Contain("john@example.com");
    }

    private static async IAsyncEnumerable<AgentResponseUpdate> EmptyStream(
        [EnumeratorCancellation] CancellationToken ct = default)
    {
        await Task.Yield();
        yield break;
    }

    private static async IAsyncEnumerable<AgentResponseUpdate> EchoStream(
        string? text, [EnumeratorCancellation] CancellationToken ct = default)
    {
        await Task.Yield();
        yield return new AgentResponseUpdate(ChatRole.Assistant, $"You said: {text}");
    }
}
