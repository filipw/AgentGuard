using AgentGuard.AgentFramework;
using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Builders;
using AgentGuard.Core.Guardrails;
using AgentGuard.Pii;
using FluentAssertions;
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;
using Xunit;

namespace AgentGuard.AgentFramework.Tests.Middleware;

// RunStreamingAsync: a buffered stream is guarded like RunAsync, a progressive one streams its text and
// holds everything else back until the final check
public class StreamingGuardTests
{
    private const string Email = "john.doe@example.com";
    private const string Secret = "ghp_abcdefghijklmnopqrstuvwxyz1234567890ab";

    [Fact]
    public async Task ShouldGuardEachStreamedMessageOnItsOwn_WhenBuffered()
    {
        var agent = Agent(b => b.RedactPii(),
            Update(new ChatResponseUpdate(ChatRole.Assistant, $"Found {Email}.") { MessageId = "m1", ResponseId = "r1" }),
            Update(new ChatResponseUpdate(ChatRole.Assistant, [new FunctionCallContent("c1", "calendar")]) { MessageId = "m1", ResponseId = "r1" }),
            Update(new ChatResponseUpdate(ChatRole.Tool, [new FunctionResultContent("c1", "busy")]) { MessageId = "m2", ResponseId = "r1" }),
            Update(new ChatResponseUpdate(ChatRole.Assistant, "She is busy today.") { MessageId = "m3", ResponseId = "r1" }));

        var response = (await Collect(agent)).ToAgentResponse();

        response.Messages.Select(m => m.MessageId).Should().Equal("m1", "m2", "m3");
        response.Messages[0].Text.Should().Be("Found <EMAIL_ADDRESS>.");
        response.Messages[0].Contents.OfType<FunctionCallContent>().Should().ContainSingle();
        response.Messages[2].Text.Should().Be("She is busy today.", "each message keeps its own text");
        response.AgentId.Should().Be("agent-1");
    }

    [Fact]
    public async Task ShouldKeepIdsUsageFinishReasonAndNonTextContent_WhenBufferedResponseIsRewritten()
    {
        var approval = new ToolApprovalRequestContent("req1", new FunctionCallContent("c1", "send_email"));
        var agent = Agent(b => b.RedactPii(),
            Update(new ChatResponseUpdate(ChatRole.Assistant, $"Emailing {Email} now.") { ResponseId = "r1", ConversationId = "conv1", MessageId = "m1" }),
            Update(new ChatResponseUpdate(ChatRole.Assistant, [approval]) { ResponseId = "r1", ConversationId = "conv1", MessageId = "m1" }),
            Update(new ChatResponseUpdate
            {
                Contents = [new UsageContent(new UsageDetails { TotalTokenCount = 42 })],
                FinishReason = ChatFinishReason.Stop,
                ResponseId = "r1",
                ConversationId = "conv1"
            }));

        var updates = await Collect(agent);
        var response = updates.ToAgentResponse();

        response.Text.Should().Be("Emailing <EMAIL_ADDRESS> now.");
        response.Messages.SelectMany(m => m.Contents).Should().Contain(approval);
        response.Usage!.TotalTokenCount.Should().Be(42);
        response.FinishReason.Should().Be(ChatFinishReason.Stop);
        updates.Should().OnlyContain(u => u.ResponseId == "r1" && u.AgentId == "agent-1");
        updates.Should().OnlyContain(u => u.AsChatResponseUpdate().ConversationId == "conv1",
            "consumers that read updates as chat updates still get the conversation id");
        updates.Select(u => u.AsChatResponseUpdate().Text).Should().NotContain(t => t.Contains(Email));
    }

    [Fact]
    public async Task ShouldCarryTheResponseIds_WhenBufferedResponseIsBlocked()
    {
        var agent = Agent(b => b.DetectSecrets().OnViolation(v => v.RejectWithMessage("Blocked.")),
            Update(new ChatResponseUpdate(ChatRole.Assistant, $"Your token is {Secret}") { ResponseId = "r1", ConversationId = "conv1", MessageId = "m1" }));

        var updates = await Collect(agent);

        var update = updates.Should().ContainSingle().Subject;
        update.Text.Should().Be("Blocked.");
        update.ResponseId.Should().Be("r1");
        update.AgentId.Should().Be("agent-1");
        update.AsChatResponseUpdate().ConversationId.Should().Be("conv1");
    }

    [Fact]
    public async Task ShouldRedactStreamedReasoning_WhenBuffered()
    {
        var agent = Agent(b => b.RedactPii(),
            Update(new ChatResponseUpdate(ChatRole.Assistant, [new TextReasoningContent($"Looking up {Email}")]) { MessageId = "m1" }),
            Update(new ChatResponseUpdate(ChatRole.Assistant, "Done.") { MessageId = "m1" }));

        var response = (await Collect(agent)).ToAgentResponse();

        GuardrailChatContent.GetReasoningText(response.Messages.Single().Contents).Should().Be("Looking up <EMAIL_ADDRESS>");
        response.Text.Should().Be("Done.");
    }

    [Fact]
    public async Task ShouldReleaseToolCallsUsageAndFinishReasonAfterTheText_WhenStreamingProgressively()
    {
        var agent = Agent(b => b.GuardToolCalls().UseProgressiveStreaming(),
            Update(new ChatResponseUpdate(ChatRole.Assistant, "Checking the weather.") { MessageId = "m1", ResponseId = "r1", ConversationId = "conv1" }),
            Update(new ChatResponseUpdate(ChatRole.Assistant,
                [new FunctionCallContent("c1", "get_weather", new Dictionary<string, object?> { ["city"] = "Oslo" })]) { MessageId = "m1", ResponseId = "r1" }),
            Update(new ChatResponseUpdate
            {
                Contents = [new UsageContent(new UsageDetails { TotalTokenCount = 42 })],
                FinishReason = ChatFinishReason.ToolCalls,
                ResponseId = "r1"
            }));

        var updates = await Collect(agent);

        var text = updates.First(u => u.Text.Length > 0);
        text.Text.Should().Be("Checking the weather.");
        text.MessageId.Should().Be("m1", "a streamed chunk keeps the ids of the update it came from");
        text.ResponseId.Should().Be("r1");
        text.AgentId.Should().Be("agent-1");
        text.AsChatResponseUpdate().ConversationId.Should().Be("conv1");

        var call = updates.FindIndex(u => u.Contents.OfType<FunctionCallContent>().Any());
        call.Should().BeGreaterThan(updates.IndexOf(text), "held back until the final check");
        updates.SelectMany(u => u.Contents).OfType<UsageContent>().Should().ContainSingle();
        updates.Should().Contain(u => u.FinishReason == ChatFinishReason.ToolCalls);
    }

    [Fact]
    public async Task ShouldDropHeldBackContent_WhenProgressiveStreamEndsBlocked()
    {
        var agent = Agent(b => b.DetectSecrets().UseProgressiveStreaming().OnViolation(v => v.RejectWithMessage("Blocked.")),
            Update(new ChatResponseUpdate(ChatRole.Assistant, $"Your token is {Secret}")),
            Update(new ChatResponseUpdate(ChatRole.Assistant, [new FunctionCallContent("c1", "rotate_token")])),
            Update(new ChatResponseUpdate { FinishReason = ChatFinishReason.ToolCalls }));

        var updates = await Collect(agent);

        updates.SelectMany(u => u.Contents).OfType<FunctionCallContent>().Should().BeEmpty();
        updates.Should().NotContain(u => u.FinishReason != null);
        Events(updates).Select(e => e.Type).Should().Equal(StreamingGuardrailEventType.Retraction, StreamingGuardrailEventType.Replacement);
        Events(updates)[1].ReplacementText.Should().Be("Blocked.");
    }

    [Fact]
    public async Task ShouldNotReleaseAToolCall_WhenTheToolCallRuleBlocksItAtTheEndOfAProgressiveStream()
    {
        var agent = Agent(b => b.GuardToolCalls().UseProgressiveStreaming(),
            Update(new ChatResponseUpdate(ChatRole.Assistant, "Running the cleanup.")),
            Update(new ChatResponseUpdate(ChatRole.Assistant,
                [new FunctionCallContent("c1", "run_sql", new Dictionary<string, object?> { ["query"] = "SELECT * FROM users; DROP TABLE users; --" })])));

        var updates = await Collect(agent);

        updates.SelectMany(u => u.Contents).OfType<FunctionCallContent>().Should().BeEmpty();
        Events(updates).Select(e => e.Type).Should().Equal(StreamingGuardrailEventType.Retraction, StreamingGuardrailEventType.Replacement);
    }

    [Fact]
    public async Task ShouldReleaseRedactedReasoning_WhenStreamingProgressively()
    {
        var agent = Agent(b => b.RedactPii().UseProgressiveStreaming(),
            Update(new ChatResponseUpdate(ChatRole.Assistant, [new TextReasoningContent($"Looking up {Email}")]) { MessageId = "m1" }),
            Update(new ChatResponseUpdate(ChatRole.Assistant, "Done.") { MessageId = "m1" }));

        var updates = await Collect(agent);

        GuardrailChatContent.GetReasoningText(updates.SelectMany(u => u.Contents)).Should().Be("Looking up <EMAIL_ADDRESS>");
    }

    private static List<StreamingGuardrailEvent> Events(List<AgentResponseUpdate> updates) =>
    [
        .. updates
            .Where(u => u.AdditionalProperties?.ContainsKey(AgentGuardMiddlewareExtensions.GuardrailEventPropertyKey) == true)
            .Select(u => (StreamingGuardrailEvent)u.AdditionalProperties![AgentGuardMiddlewareExtensions.GuardrailEventPropertyKey]!)
    ];

    // an update as ChatClientAgent produces it: the chat update as its raw representation
    private static AgentResponseUpdate Update(ChatResponseUpdate update) => new(update) { AgentId = "agent-1" };

    private static AIAgent Agent(Action<GuardrailPolicyBuilder> configure, params AgentResponseUpdate[] updates) =>
        new TestAgent(
                (_, _, _, _) => throw new NotSupportedException(),
                (_, _, _, ct) => updates.ToAsyncEnumerable(ct))
            .AsBuilder()
            .UseAgentGuard(configure)
            .Build();

    private static async Task<List<AgentResponseUpdate>> Collect(AIAgent agent)
    {
        var list = new List<AgentResponseUpdate>();
        await foreach (var update in agent.RunStreamingAsync("go ahead"))
            list.Add(update);
        return list;
    }
}
