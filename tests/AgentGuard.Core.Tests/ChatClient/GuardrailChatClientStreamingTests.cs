using System.Runtime.CompilerServices;
using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Builders;
using AgentGuard.Core.ChatClient;
using AgentGuard.Core.Guardrails;
using AgentGuard.Pii;
using FluentAssertions;
using Microsoft.Extensions.AI;
using Xunit;

namespace AgentGuard.Core.Tests.ChatClient;

// streamed responses: buffered ones are guarded like non-streamed ones, progressive ones stream their
// text and hold everything else back until the final check
public class GuardrailChatClientStreamingTests
{
    private const string Email = "john.doe@example.com";
    private const string Secret = "ghp_abcdefghijklmnopqrstuvwxyz1234567890ab";

    [Fact]
    public async Task ShouldGuardEachStreamedMessageOnItsOwn_WhenBuffered()
    {
        var client = Client(g => g.RedactPii(),
            new ChatResponseUpdate(ChatRole.Assistant, $"Found {Email}.") { MessageId = "m1", ResponseId = "r1" },
            new ChatResponseUpdate(ChatRole.Assistant, [new FunctionCallContent("c1", "calendar")]) { MessageId = "m1", ResponseId = "r1" },
            new ChatResponseUpdate(ChatRole.Tool, [new FunctionResultContent("c1", "busy")]) { MessageId = "m2", ResponseId = "r1" },
            new ChatResponseUpdate(ChatRole.Assistant, "She is busy today.") { MessageId = "m3", ResponseId = "r1" });

        var response = (await Collect(client)).ToChatResponse();

        response.Messages.Select(m => m.MessageId).Should().Equal("m1", "m2", "m3");
        response.Messages[0].Text.Should().Be("Found <EMAIL_ADDRESS>.");
        response.Messages[0].Contents.OfType<FunctionCallContent>().Should().ContainSingle();
        response.Messages[1].Contents.OfType<FunctionResultContent>().Should().ContainSingle();
        response.Messages[2].Text.Should().Be("She is busy today.", "each message keeps its own text");
    }

    [Fact]
    public async Task ShouldKeepIdsUsageFinishReasonTokenAndNonTextContent_WhenBufferedResponseIsRewritten()
    {
        var token = ResponseContinuationToken.FromBytes(new byte[] { 1, 2, 3 });
        var approval = new ToolApprovalRequestContent("req1", new FunctionCallContent("c1", "send_email"));
        var client = Client(g => g.RedactPii(),
            new ChatResponseUpdate(ChatRole.Assistant, $"Emailing {Email} now.") { ResponseId = "r1", ConversationId = "conv1", MessageId = "m1", ModelId = "model" },
            new ChatResponseUpdate(ChatRole.Assistant, [approval]) { ResponseId = "r1", ConversationId = "conv1", MessageId = "m1" },
            new ChatResponseUpdate
            {
                Contents = [new UsageContent(new UsageDetails { TotalTokenCount = 42 })],
                FinishReason = ChatFinishReason.Stop,
                ResponseId = "r1",
                ConversationId = "conv1",
                ContinuationToken = token
            });

        var updates = await Collect(client);
        var response = updates.ToChatResponse();

        response.Text.Should().Be("Emailing <EMAIL_ADDRESS> now.");
        response.Messages.Single().MessageId.Should().Be("m1");
        response.Messages.SelectMany(m => m.Contents).Should().Contain(approval);
        response.Usage!.TotalTokenCount.Should().Be(42);
        response.FinishReason.Should().Be(ChatFinishReason.Stop);
        response.ModelId.Should().Be("model");
        updates.Should().OnlyContain(u => u.ResponseId == "r1" && u.ConversationId == "conv1");
        updates.Should().Contain(u => u.ContinuationToken == token);
    }

    [Fact]
    public async Task ShouldCarryTheResponseIds_WhenBufferedResponseIsBlocked()
    {
        var client = Client(g => g.DetectSecrets().OnViolation(v => v.RejectWithMessage("Blocked.")),
            new ChatResponseUpdate(ChatRole.Assistant, $"Your token is {Secret}") { ResponseId = "r1", ConversationId = "conv1", MessageId = "m1" },
            new ChatResponseUpdate { FinishReason = ChatFinishReason.Stop, ResponseId = "r1", ConversationId = "conv1" });

        var updates = await Collect(client);

        var update = updates.Should().ContainSingle().Subject;
        update.Text.Should().Be("Blocked.");
        update.ResponseId.Should().Be("r1");
        update.ConversationId.Should().Be("conv1");
    }

    [Fact]
    public async Task ShouldRedactStreamedReasoning_WhenBuffered()
    {
        var client = Client(g => g.RedactPii(),
            new ChatResponseUpdate(ChatRole.Assistant, [new TextReasoningContent($"Looking up {Email}")]) { MessageId = "m1" },
            new ChatResponseUpdate(ChatRole.Assistant, "Done.") { MessageId = "m1" });

        var response = (await Collect(client)).ToChatResponse();

        GuardrailChatContent.GetReasoningText(response.Messages.Single().Contents).Should().Be("Looking up <EMAIL_ADDRESS>");
        response.Text.Should().Be("Done.");
    }

    [Fact]
    public async Task ShouldReleaseToolCallsUsageAndFinishReasonAfterTheText_WhenStreamingProgressively()
    {
        var client = Client(g => g.GuardToolCalls().UseProgressiveStreaming(),
            new ChatResponseUpdate(ChatRole.Assistant, "Checking the weather.") { MessageId = "m1", ResponseId = "r1", ConversationId = "conv1" },
            new ChatResponseUpdate(ChatRole.Assistant,
                [new FunctionCallContent("c1", "get_weather", new Dictionary<string, object?> { ["city"] = "Oslo" })]) { MessageId = "m1", ResponseId = "r1" },
            new ChatResponseUpdate
            {
                Contents = [new UsageContent(new UsageDetails { TotalTokenCount = 42 })],
                FinishReason = ChatFinishReason.ToolCalls,
                ResponseId = "r1"
            });

        var updates = await Collect(client);

        var text = updates.First(u => u.Text.Length > 0);
        text.Text.Should().Be("Checking the weather.");
        text.MessageId.Should().Be("m1", "a streamed chunk keeps the ids of the update it came from");
        text.ResponseId.Should().Be("r1");
        text.ConversationId.Should().Be("conv1");

        var call = updates.FindIndex(u => u.Contents.OfType<FunctionCallContent>().Any());
        call.Should().BeGreaterThan(updates.IndexOf(text), "held back until the final check");
        updates.SelectMany(u => u.Contents).OfType<UsageContent>().Should().ContainSingle();
        updates.Should().Contain(u => u.FinishReason == ChatFinishReason.ToolCalls);
    }

    [Fact]
    public async Task ShouldDropHeldBackContent_WhenProgressiveStreamEndsBlocked()
    {
        var client = Client(g => g.DetectSecrets().UseProgressiveStreaming().OnViolation(v => v.RejectWithMessage("Blocked.")),
            new ChatResponseUpdate(ChatRole.Assistant, $"Your token is {Secret}"),
            new ChatResponseUpdate(ChatRole.Assistant, [new FunctionCallContent("c1", "rotate_token")]),
            new ChatResponseUpdate { FinishReason = ChatFinishReason.ToolCalls });

        var updates = await Collect(client);

        updates.SelectMany(u => u.Contents).OfType<FunctionCallContent>().Should().BeEmpty();
        updates.Should().NotContain(u => u.FinishReason != null);
        Events(updates).Select(e => e.Type).Should().Equal(StreamingGuardrailEventType.Retraction, StreamingGuardrailEventType.Replacement);
        Events(updates)[1].ReplacementText.Should().Be("Blocked.");
    }

    [Fact]
    public async Task ShouldNotReleaseAToolCall_WhenTheToolCallRuleBlocksItAtTheEndOfAProgressiveStream()
    {
        var client = Client(g => g.GuardToolCalls().UseProgressiveStreaming(),
            new ChatResponseUpdate(ChatRole.Assistant, "Running the cleanup."),
            new ChatResponseUpdate(ChatRole.Assistant,
                [new FunctionCallContent("c1", "run_sql", new Dictionary<string, object?> { ["query"] = "SELECT * FROM users; DROP TABLE users; --" })]));

        var updates = await Collect(client);

        updates.SelectMany(u => u.Contents).OfType<FunctionCallContent>().Should().BeEmpty();
        Events(updates).Select(e => e.Type).Should().Equal(StreamingGuardrailEventType.Retraction, StreamingGuardrailEventType.Replacement);
    }

    [Fact]
    public async Task ShouldReleaseRedactedReasoning_WhenStreamingProgressively()
    {
        var client = Client(g => g.RedactPii().UseProgressiveStreaming(),
            new ChatResponseUpdate(ChatRole.Assistant, [new TextReasoningContent($"Looking up {Email}")]) { MessageId = "m1" },
            new ChatResponseUpdate(ChatRole.Assistant, "Done.") { MessageId = "m1" });

        var updates = await Collect(client);

        GuardrailChatContent.GetReasoningText(updates.SelectMany(u => u.Contents)).Should().Be("Looking up <EMAIL_ADDRESS>");
    }

    private static List<StreamingGuardrailEvent> Events(List<ChatResponseUpdate> updates) =>
    [
        .. updates
            .Where(u => u.AdditionalProperties?.ContainsKey(GuardrailChatClient.GuardrailEventPropertyKey) == true)
            .Select(u => (StreamingGuardrailEvent)u.AdditionalProperties![GuardrailChatClient.GuardrailEventPropertyKey]!)
    ];

    private static IChatClient Client(Action<GuardrailPolicyBuilder> configure, params ChatResponseUpdate[] updates) =>
        new StreamingChatClient(updates).UseAgentGuard(configure);

    private static async Task<List<ChatResponseUpdate>> Collect(IChatClient client)
    {
        var list = new List<ChatResponseUpdate>();
        await foreach (var update in client.GetStreamingResponseAsync([new ChatMessage(ChatRole.User, "go ahead")]))
            list.Add(update);
        return list;
    }

    private sealed class StreamingChatClient(IReadOnlyList<ChatResponseUpdate> updates) : IChatClient
    {
        public Task<ChatResponse> GetResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public async IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(
            IEnumerable<ChatMessage> messages, ChatOptions? options = null, [EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            foreach (var update in updates)
            {
                await Task.Yield();
                yield return update;
            }
        }

        public object? GetService(Type serviceType, object? serviceKey = null) => null;

        public void Dispose()
        {
        }
    }
}
