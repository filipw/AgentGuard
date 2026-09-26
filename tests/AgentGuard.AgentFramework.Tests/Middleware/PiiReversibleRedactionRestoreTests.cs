using System.Globalization;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.RegularExpressions;
using AgentGuard.AgentFramework;
using AgentGuard.Core.Abstractions;
using FluentAssertions;
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;
using TasmanianDevil.Anonymizer.Operators;
using Xunit;

namespace AgentGuard.AgentFramework.Tests.Middleware;

// only tokens minted for the conversation come back - the request's, and the session's from earlier turns -
// wherever they appear in the response, and a streamed response reads the same as the one without streaming
public partial class PiiReversibleRedactionRestoreTests
{
    private const string Key = "0123456789abcdef";
    private const string Email = "john@example.com";
    private const string Request = $"my email is {Email}";

    // valid base64url whose first byte is the token format's 0x01, but not a token
    private const string NotAToken = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA";

    private static readonly byte[] KeyBytes = Encoding.UTF8.GetBytes(Key);
    private static readonly byte[] OtherKeyBytes = Encoding.UTF8.GetBytes("fedcba9876543210");

    [Fact]
    public async Task ShouldRestoreToken_WhenStreamSplitsItAcrossTwoUpdates()
    {
        var agent = BuildAgent(token => [$"Your email is {token}."], text => SplitInsideToken(text));

        var text = await StreamTextAsync(agent, Request);

        text.Should().Be($"Your email is {Email}.");
    }

    [Fact]
    public async Task ShouldRestoreToken_WhenStreamSendsOneCharacterPerUpdate()
    {
        var agent = BuildAgent(token => [$"Your email is {token}."], text => Chunk(text, 1));

        var text = await StreamTextAsync(agent, Request);

        text.Should().Be($"Your email is {Email}.");
    }

    [Fact]
    public async Task ShouldRestoreTokenInTheUpdateThatCompletesIt_WhenStreamEndsWithIt()
    {
        var agent = BuildAgent(token => [$"Your email is {token}"], text => Chunk(text, 1));

        var updates = await CollectAsync(agent.RunStreamingAsync(Request));

        string.Concat(updates.Select(u => u.Text)).Should().Be($"Your email is {Email}");
        var last = updates[^1];
        last.Text.Should().Be(Email);
        last.MessageId.Should().Be("m0");
        last.Role.Should().Be(ChatRole.Assistant);
    }

    [Fact]
    public async Task ShouldFlushHeldText_WhenStreamEndsPartWayThroughAToken()
    {
        var partial = "";
        var agent = BuildAgent(
            token =>
            {
                partial = token[..30];
                return [$"Your email is {partial}"];
            },
            text => Chunk(text, 1));

        var updates = await CollectAsync(agent.RunStreamingAsync(Request));

        string.Concat(updates.Select(u => u.Text)).Should().Be($"Your email is {partial}");
        var flushed = updates[^1];
        flushed.Text.Should().Be(partial, "the start of a token is held until the stream ends, then goes out as it was");
        flushed.MessageId.Should().Be("m0");
        flushed.Role.Should().Be(ChatRole.Assistant);
    }

    [Fact]
    public async Task ShouldKeepNonTextContentAndMetadata_WhenStreamedTokenIsRestored()
    {
        var photo = new DataContent(new byte[] { 1, 2, 3 }, "image/png");
        var usage = new UsageContent(new UsageDetails { InputTokenCount = 10, OutputTokenCount = 5, TotalTokenCount = 15 });
        var createdAt = new DateTimeOffset(2026, 9, 26, 8, 30, 0, TimeSpan.Zero);

        var agent = new TestAgent(
            (_, _, _, _) => throw new NotSupportedException(),
            (messages, _, _, ct) =>
            {
                var token = TokenIn(messages.Last().Text);
                return Stream(
                [
                    new AgentResponseUpdate(ChatRole.Assistant, [new TextContent("Your email is "), new TextContent(token[..20])])
                    {
                        MessageId = "m1",
                        ResponseId = "r1",
                        AuthorName = "bot",
                        AgentId = "agent-1",
                        CreatedAt = createdAt,
                        AdditionalProperties = new() { ["seq"] = 1 }
                    },
                    new AgentResponseUpdate(null, [new TextContent(token[20..]), photo])
                    {
                        MessageId = "m1",
                        ResponseId = "r1",
                        AdditionalProperties = new() { ["seq"] = 2 }
                    },
                    new AgentResponseUpdate(null, [new TextContent("."), usage])
                    {
                        MessageId = "m1",
                        ResponseId = "r1",
                        FinishReason = ChatFinishReason.Stop
                    }
                ], ct);
            })
            .AsBuilder()
            .UsePiiReversibleRedaction(Key)
            .Build(null!);

        var updates = await CollectAsync(agent.RunStreamingAsync(Request));

        string.Concat(updates.Select(u => u.Text)).Should().Be($"Your email is {Email}.");
        updates.Should().OnlyContain(u => u.MessageId == "m1" && u.ResponseId == "r1");

        var first = updates[0];
        first.AuthorName.Should().Be("bot");
        first.AgentId.Should().Be("agent-1");
        first.CreatedAt.Should().Be(createdAt);
        first.AdditionalProperties.Should().Contain("seq", 1);

        var withPhoto = updates.Should().ContainSingle(u => u.Contents.Contains(photo)).Subject;
        withPhoto.AdditionalProperties.Should().Contain("seq", 2);

        var withUsage = updates.Should().ContainSingle(u => u.Contents.Contains(usage)).Subject;
        withUsage.FinishReason.Should().Be(ChatFinishReason.Stop);

        var response = updates.ToAgentResponse();
        var message = response.Messages.Should().ContainSingle().Subject;
        message.Text.Should().Be($"Your email is {Email}.");
        message.Contents.Should().Contain(photo);
        response.Usage!.TotalTokenCount.Should().Be(15);
        response.FinishReason.Should().Be(ChatFinishReason.Stop);
    }

    [Theory]
    [InlineData("contact{0}")]
    [InlineData("{0}_2 is on file")]
    [InlineData("Write to __{0}__ today.")]
    [InlineData("Write to **{0}**.")]
    [InlineData("twice: {0}{0}")]
    public async Task ShouldRestoreToken_WhenItIsRunTogetherWithOtherCharacters(string reply)
    {
        var agent = BuildAgent(token => [string.Format(CultureInfo.InvariantCulture, reply, token)], text => Chunk(text, 1));

        var response = await agent.RunAsync(Request);
        var streamed = await StreamTextAsync(agent, Request);

        var expected = string.Format(CultureInfo.InvariantCulture, reply, Email);
        response.Text.Should().Be(expected);
        streamed.Should().Be(expected);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(7)]
    [InlineData(40)]
    [InlineData(1000)]
    public async Task ShouldStreamTheSameTextAsWithoutStreaming_WhenResponseHasSeveralMessages(int chunkSize)
    {
        // encrypted with the same key, but not by this middleware for this conversation
        var outsider = AesCipher.Encrypt(KeyBytes, "alice@example.com");
        var foreign = AesCipher.Encrypt(OtherKeyBytes, "mallory@example.com");
        var minted = new List<string>();
        var agent = BuildAgent(
            token =>
            {
                minted.Add(token);
                return
                [
                    $"Emailing {token}",
                    $"{outsider} and _{token}_ and x{token}y; {foreign}, {NotAToken} and {token[..30]} stay as they are.",
                ];
            },
            text => Chunk(text, chunkSize));

        var response = await agent.RunAsync(Request);
        var streamed = (await CollectAsync(agent.RunStreamingAsync(Request))).ToAgentResponse();

        response.Messages.Select(m => m.Text).Should().Equal(Expected(minted[0]));
        streamed.Messages.Select(m => m.Text).Should().Equal(Expected(minted[1]));

        string[] Expected(string token) =>
        [
            $"Emailing {Email}",
            $"{outsider} and _{Email}_ and x{Email}y; {foreign}, {NotAToken} and {token[..30]} stay as they are."
        ];
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ShouldRestoreTokenFromAnEarlierTurn_WhenSessionHistoryReplaysIt(bool streaming)
    {
        // the second turn has no PII of its own; the model echoes the token the first turn stored
        var (agent, model) = BuildSessionAgent(RecallEmail);
        var session = await agent.CreateSessionAsync();

        await RunAsync(agent, Request, session, streaming);
        var answer = await RunAsync(agent, "what is my email?", session, streaming);

        model.Calls[1].Select(m => m.Text).Should().NotContain(t => t.Contains(Email), "the history holds only the token");
        answer.Should().Be($"Your email is {Email}.");
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ShouldRestoreTokenFromAnEarlierTurn_WhenSessionIsSerializedAndRestored(bool streaming)
    {
        var (agent, _) = BuildSessionAgent(RecallEmail);
        var session = await agent.CreateSessionAsync();
        await RunAsync(agent, Request, session, streaming);

        var serialized = await agent.SerializeSessionAsync(session);
        var restored = await agent.DeserializeSessionAsync(serialized);
        var answer = await RunAsync(agent, "what is my email?", restored, streaming);

        serialized.GetRawText().Should().Contain(PiiTokenRegistry.StateKey).And.NotContain(Email, "the session keeps only tokens");
        answer.Should().Be($"Your email is {Email}.");
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ShouldNotRestoreToken_WhenItWasMintedForAnotherSession(bool streaming)
    {
        var (agent, model) = BuildSessionAgent(EchoLastUserMessage);

        var first = await agent.CreateSessionAsync();
        var echoed = await RunAsync(agent, Request, first, streaming);
        var token = TokenIn(model.Calls[0].Last(m => m.Role == ChatRole.User).Text);

        var second = await agent.CreateSessionAsync();
        var answer = await RunAsync(agent, $"what is {token}?", second, streaming);

        echoed.Should().Be($"You said: {Request}");
        answer.Should().Be($"You said: what is {token}?", "a token pasted from elsewhere is not decrypted");
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ShouldRestoreOnlyTheRequestsTokens_WhenRunHasNoSession(bool streaming)
    {
        var received = new List<string>();
        var agent = BuildEchoAgent(received);

        await RunAsync(agent, Request, session: null, streaming);
        var earlier = TokenIn(received[0]);
        var answer = await RunAsync(agent, $"compare {earlier} with jane@example.com", session: null, streaming);

        received[1].Should().NotContain("jane@example.com");
        answer.Should().Be($"You said: compare {earlier} with jane@example.com");
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ShouldNotRestoreToken_WhenSessionListNoLongerHoldsIt(bool streaming)
    {
        var (agent, _) = BuildSessionAgent(RecallEmail);
        var session = await agent.CreateSessionAsync();
        await RunAsync(agent, Request, session, streaming);
        var token = PiiTokenRegistry.Read(session).Should().ContainSingle().Subject;

        PiiTokenRegistry.Record(session, Enumerable.Range(0, PiiTokenRegistry.Capacity).Select(i => AesCipher.Encrypt(KeyBytes, $"user{i}")));
        var answer = await RunAsync(agent, "what is my email?", session, streaming);

        PiiTokenRegistry.Read(session).Should().HaveCount(PiiTokenRegistry.Capacity).And.NotContain(token);
        answer.Should().Be($"Your email is {token}.");
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ShouldLeaveRecordedToken_WhenTheKeyCannotDecryptIt(bool streaming)
    {
        // recorded for the session, but encrypted with a key the agent no longer uses
        var stale = AesCipher.Encrypt(OtherKeyBytes, "mallory@example.com");
        var (agent, _) = BuildSessionAgent((_, _) => $"Your code is {stale}, and x{stale}.");
        var session = await agent.CreateSessionAsync();
        PiiTokenRegistry.Record(session, [stale]);

        var answer = await RunAsync(agent, "what is my code?", session, streaming);

        answer.Should().Be($"Your code is {stale}, and x{stale}.");
    }

    [Theory]
    [InlineData("Pneumonoultramicroscopicsilicovolcanoconiosis is one long word.")]
    [InlineData("Abracadabra_Abracadabra_Abracadabra_Abracadabra is no token either.")]
    [InlineData("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")]
    [InlineData("sha1 da39a3ee5e6b4b0d3255bfef95601890afd80709")]
    [InlineData("payload " + NotAToken + " ends here")]
    public async Task ShouldLeaveTextUnchanged_WhenItOnlyLooksLikeAToken(string text)
    {
        var agent = BuildAgent(_ => [text], reply => Chunk(reply, 1));

        var response = await agent.RunAsync(Request);
        var streamed = await StreamTextAsync(agent, Request);

        response.Text.Should().Be(text);
        streamed.Should().Be(text);
    }

    [Fact]
    public async Task ShouldLeaveTokenUnchanged_WhenModelAltersIt()
    {
        var altered = new List<string>();
        var agent = BuildAgent(
            token =>
            {
                altered.Add(token[..^1] + (token[^1] == 'x' ? 'y' : 'x'));
                return [$"Your email is {altered[^1]}."];
            },
            reply => Chunk(reply, 1));

        var response = await agent.RunAsync(Request);
        var streamed = await StreamTextAsync(agent, Request);

        response.Text.Should().Be($"Your email is {altered[0]}.");
        streamed.Should().Be($"Your email is {altered[1]}.");
    }

    [Fact]
    public async Task ShouldLeaveTokenUnchanged_WhenSameKeyEncryptedItOutsideTheConversation()
    {
        var outsider = AesCipher.Encrypt(KeyBytes, "mallory@example.com");
        var agent = BuildAgent(_ => [$"The address is {outsider}."], reply => Chunk(reply, 3));

        var response = await agent.RunAsync(Request);
        var streamed = await StreamTextAsync(agent, Request);

        response.Text.Should().Be($"The address is {outsider}.");
        streamed.Should().Be($"The address is {outsider}.");
    }

    [Fact]
    public async Task ShouldLeaveTokenUnchanged_WhenAnotherKeyEncryptedIt()
    {
        var foreign = AesCipher.Encrypt(OtherKeyBytes, "mallory@example.com");
        var agent = BuildAgent(_ => [$"The address is {foreign}."], reply => Chunk(reply, 3));

        var response = await agent.RunAsync(Request);
        var streamed = await StreamTextAsync(agent, Request);

        response.Text.Should().Be($"The address is {foreign}.");
        streamed.Should().Be($"The address is {foreign}.");
    }

    [Fact]
    public async Task ShouldReleaseHeldTextBeforeGuardrailEvent_WhenStreamCarriesOne()
    {
        var blocked = GuardrailResult.Blocked("no emails");
        var agent = new TestAgent(
            (_, _, _, _) => throw new NotSupportedException(),
            (messages, _, _, ct) =>
            {
                var token = TokenIn(messages.Last().Text);
                var replacement = new AgentResponseUpdate(ChatRole.Assistant, "Sorry, I can't share that.")
                {
                    MessageId = "m1",
                    AdditionalProperties = new()
                    {
                        [AgentGuardMiddlewareExtensions.GuardrailEventPropertyKey] =
                            StreamingGuardrailEvent.Replace("Sorry, I can't share that.", blocked, 40)
                    }
                };

                return Stream(
                [
                    new AgentResponseUpdate(ChatRole.Assistant, $"Your email is {token[..25]}") { MessageId = "m1" },
                    replacement
                ], ct);
            })
            .AsBuilder()
            .UsePiiReversibleRedaction(Key)
            .Build(null!);

        var updates = await CollectAsync(agent.RunStreamingAsync(Request));

        updates.Should().HaveCount(3);
        updates[0].Text.Should().Be("Your email is ");
        updates[1].Text.Should().MatchRegex("^A[Q-Za-f][A-Za-z0-9_-]{23}$", "the unfinished token goes out as it was, before the event");
        updates[2].Text.Should().Be("Sorry, I can't share that.");
        updates[2].AdditionalProperties.Should().ContainKey(AgentGuardMiddlewareExtensions.GuardrailEventPropertyKey);
    }

    // an agent without a session that answers with the messages reply(token) makes from the request's token,
    // whole or streamed in the pieces split makes of each message
    private static AIAgent BuildAgent(Func<string, string[]> reply, Func<string, IEnumerable<string>> split) =>
        new TestAgent(
            (messages, _, _, _) =>
            {
                var texts = reply(TokenInOrEmpty(messages.Last().Text));
                return Task.FromResult(new AgentResponse(
                    [.. texts.Select((text, i) => new ChatMessage(ChatRole.Assistant, text) { MessageId = $"m{i}" })]));
            },
            (messages, _, _, ct) =>
            {
                var texts = reply(TokenInOrEmpty(messages.Last().Text));
                return Stream(
                    texts.SelectMany((text, i) => split(text).Select(piece => new AgentResponseUpdate(ChatRole.Assistant, piece) { MessageId = $"m{i}" })),
                    ct);
            })
            .AsBuilder()
            .UsePiiReversibleRedaction(Key)
            .Build(null!);

    // an agent without a session that repeats the request's last message, recording what it received
    private static AIAgent BuildEchoAgent(List<string> received) =>
        new TestAgent(
            (messages, _, _, _) =>
            {
                received.Add(messages.Last().Text);
                return Task.FromResult(new AgentResponse(new ChatMessage(ChatRole.Assistant, $"You said: {messages.Last().Text}")));
            },
            (messages, _, _, ct) =>
            {
                received.Add(messages.Last().Text);
                return Stream(Chunk($"You said: {messages.Last().Text}", 1).Select(piece => new AgentResponseUpdate(ChatRole.Assistant, piece)), ct);
            })
            .AsBuilder()
            .UsePiiReversibleRedaction(Key)
            .Build(null!);

    // a chat client agent that keeps its history in the session, over a model that answers each call with
    // answer(messages, call), whole or one character per update
    private static (AIAgent Agent, ScriptedChatClient Model) BuildSessionAgent(Func<IReadOnlyList<ChatMessage>, int, string> answer)
    {
        var model = new ScriptedChatClient(
            (messages, call) => new ChatResponse(new ChatMessage(ChatRole.Assistant, answer(messages, call))),
            (messages, call) => [.. Chunk(answer(messages, call), 1).Select(piece => new ChatResponseUpdate(ChatRole.Assistant, piece) { MessageId = $"m{call}" })]);

        return (model.AsAIAgent(instructions: "a", name: "a").AsBuilder().UsePiiReversibleRedaction(Key).Build(), model);
    }

    private static string RecallEmail(IReadOnlyList<ChatMessage> messages, int call) =>
        call == 0 ? "Noted." : $"Your email is {TokenIn(messages.First(m => m.Role == ChatRole.User).Text)}.";

    private static string EchoLastUserMessage(IReadOnlyList<ChatMessage> messages, int call) =>
        $"You said: {messages.Last(m => m.Role == ChatRole.User).Text}";

    [GeneratedRegex("A[Q-Za-f][A-Za-z0-9_-]{37,}")]
    private static partial Regex TokenPattern();

    private static string TokenIn(string text) =>
        TokenPattern().Match(text) is { Success: true } match ? match.Value : throw new InvalidOperationException($"no token in '{text}'");

    private static string TokenInOrEmpty(string text) => TokenPattern().Match(text).Value;

    private static IEnumerable<string> Chunk(string text, int size)
    {
        for (var i = 0; i < text.Length; i += size)
            yield return text.Substring(i, Math.Min(size, text.Length - i));
    }

    private static IEnumerable<string> SplitInsideToken(string text)
    {
        var token = TokenPattern().Match(text);
        var cut = token.Index + (token.Length / 2);
        return [text[..cut], text[cut..]];
    }

    private static async IAsyncEnumerable<AgentResponseUpdate> Stream(
        IEnumerable<AgentResponseUpdate> updates, [EnumeratorCancellation] CancellationToken ct = default)
    {
        foreach (var update in updates)
        {
            await Task.Yield();
            ct.ThrowIfCancellationRequested();
            yield return update;
        }
    }

    private static async Task<List<AgentResponseUpdate>> CollectAsync(IAsyncEnumerable<AgentResponseUpdate> updates)
    {
        var collected = new List<AgentResponseUpdate>();
        await foreach (var update in updates)
            collected.Add(update);
        return collected;
    }

    private static async Task<string> StreamTextAsync(AIAgent agent, string message) =>
        string.Concat((await CollectAsync(agent.RunStreamingAsync(message))).Select(u => u.Text));

    private static async Task<string> RunAsync(AIAgent agent, string message, AgentSession? session, bool streaming) =>
        streaming
            ? string.Concat((await CollectAsync(agent.RunStreamingAsync(message, session))).Select(u => u.Text))
            : (await agent.RunAsync(message, session)).Text;
}
