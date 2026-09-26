using System.Runtime.CompilerServices;
using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Builders;
using AgentGuard.Core.Guardrails;
using AgentGuard.Core.Ledger;
using AgentGuard.Pii;
using FluentAssertions;
using Microsoft.Extensions.AI;
using Xunit;

namespace AgentGuard.Core.Tests.Guardrails;

public class ChatMessageGuardTests
{
    private const string Email = "john.doe@example.com";
    private const string Secret = "ghp_abcdefghijklmnopqrstuvwxyz1234567890ab";

    [Fact]
    public async Task ShouldRedactReasoning_WhenReasoningContainsPii()
    {
        var guard = new ChatMessageGuard(new GuardrailPolicyBuilder().RedactPii().Build());
        var message = new ChatMessage(ChatRole.Assistant,
            [new TextReasoningContent($"The user's email is {Email}."), new TextContent("I have updated your account.")]);

        var result = await guard.GuardOutputAsync([message]);

        result.IsBlocked.Should().BeFalse();
        result.WasModified.Should().BeTrue();
        GuardrailChatContent.GetReasoningText(result.Messages[0].Contents).Should().Be("The user's email is <EMAIL_ADDRESS>.");
        result.Messages[0].Text.Should().Be("I have updated your account.");
    }

    [Fact]
    public async Task ShouldRemoveReasoningText_AndKeepTheAnswer_WhenReasoningIsBlocked()
    {
        var guard = new ChatMessageGuard(new GuardrailPolicyBuilder().DetectSecrets().Build());
        var message = new ChatMessage(ChatRole.Assistant,
        [
            new TextReasoningContent($"The key is {Secret}."),
            new TextReasoningContent("") { ProtectedData = "encrypted" },
            new TextContent("I can't share keys.")
        ]);

        var result = await guard.GuardOutputAsync([message]);

        result.IsBlocked.Should().BeFalse("a block on the reasoning alone does not block the answer");
        result.WasModified.Should().BeTrue();
        var guarded = result.Messages.Single();
        GuardrailChatContent.GetReasoningText(guarded.Contents).Should().BeEmpty();
        guarded.Contents.OfType<TextReasoningContent>().Should().ContainSingle().Which.ProtectedData.Should().Be("encrypted");
        guarded.Text.Should().Be("I can't share keys.");
    }

    [Fact]
    public async Task ShouldKeepProtectedData_WhenReasoningIsRewritten()
    {
        var guard = new ChatMessageGuard(new GuardrailPolicyBuilder().RedactPii().Build());
        var call = new FunctionCallContent("c1", "lookup");
        var message = new ChatMessage(ChatRole.Assistant,
            [new TextReasoningContent($"Look up {Email}") { ProtectedData = "encrypted" }, call]);

        var result = await guard.GuardOutputAsync([message]);

        var reasoning = result.Messages.Single().Contents.OfType<TextReasoningContent>().Single();
        reasoning.Text.Should().Be("Look up <EMAIL_ADDRESS>");
        reasoning.ProtectedData.Should().Be("encrypted");
        result.Messages.Single().Contents.Should().Contain(call);
    }

    [Fact]
    public async Task ShouldDropTheMessage_WhenBlockedReasoningWasAllItHeld()
    {
        var guard = new ChatMessageGuard(new GuardrailPolicyBuilder().DetectSecrets().Build());

        var result = await guard.GuardOutputAsync(
        [
            new ChatMessage(ChatRole.Assistant, [new TextReasoningContent($"The key is {Secret}.")]),
            new ChatMessage(ChatRole.Assistant, "Done.")
        ]);

        result.Messages.Should().ContainSingle().Which.Text.Should().Be("Done.");
    }

    [Fact]
    public async Task ShouldNotReask_WhenOnlyTheReasoningIsBlocked()
    {
        var reask = new CountingChatClient("regenerated answer");
        var guard = new ChatMessageGuard(new GuardrailPolicyBuilder()
            .ValidateOutput(t => !t.Contains("forbidden", StringComparison.Ordinal), "forbidden")
            .EnableReask(reask)
            .Build());
        var message = new ChatMessage(ChatRole.Assistant,
            [new TextReasoningContent("a forbidden line of thought"), new TextContent("A fine answer.")]);

        var result = await guard.GuardOutputAsync([message]);

        reask.Calls.Should().Be(0, "a regenerated answer can't stand in for reasoning");
        result.Messages.Single().Text.Should().Be("A fine answer.");
        GuardrailChatContent.GetReasoningText(result.Messages.Single().Contents).Should().BeEmpty();
    }

    [Fact]
    public async Task ShouldDropTheReasoningOfTheReplacedAnswer_WhenReaskSucceeds()
    {
        var reask = new CountingChatClient("compliant answer");
        var guard = new ChatMessageGuard(new GuardrailPolicyBuilder()
            .ValidateOutput(t => !t.Contains("COMPETITOR", StringComparison.Ordinal), "mentions a competitor")
            .EnableReask(reask)
            .Build());
        var message = new ChatMessage(ChatRole.Assistant,
        [
            new TextReasoningContent("comparing vendors") { ProtectedData = "encrypted" },
            new TextContent("buy from COMPETITOR")
        ]);

        var result = await guard.GuardOutputAsync([message]);

        var guarded = result.Messages.Single();
        guarded.Text.Should().Be("compliant answer");
        GuardrailChatContent.GetReasoningText(guarded.Contents).Should().BeEmpty("the reasoning belonged to the answer the re-ask replaced");
        guarded.Contents.OfType<TextReasoningContent>().Single().ProtectedData.Should().Be("encrypted");
    }

    [Fact]
    public async Task ShouldBlockAToolCall_WithoutReask_WhenTheResponseHasNoText()
    {
        var reask = new CountingChatClient("regenerated answer");
        var guard = new ChatMessageGuard(new GuardrailPolicyBuilder().GuardToolCalls().EnableReask(reask).Build());
        var message = new ChatMessage(ChatRole.Assistant,
        [
            new FunctionCallContent("c1", "run_sql", new Dictionary<string, object?> { ["query"] = "SELECT * FROM users; DROP TABLE users; --" })
        ]);

        var result = await guard.GuardOutputAsync([message]);

        result.IsBlocked.Should().BeTrue();
        reask.Calls.Should().Be(0, "a regenerated answer can't stand in for a tool call");
    }

    [Fact]
    public async Task ShouldStillCheckTheToolCalls_WhenAReaskReplacesTheAnswerBeforeItsFinalText()
    {
        var reask = new CountingChatClient("compliant answer");
        var guard = new ChatMessageGuard(new GuardrailPolicyBuilder()
            .ValidateOutput(t => !t.Contains("COMPETITOR", StringComparison.Ordinal), "mentions a competitor")
            .GuardToolCalls()
            .EnableReask(reask)
            .Build());

        var result = await guard.GuardOutputAsync(
        [
            new ChatMessage(ChatRole.Assistant, "buy from COMPETITOR"),
            new ChatMessage(ChatRole.Assistant,
            [
                new FunctionCallContent("c1", "run_sql", new Dictionary<string, object?> { ["query"] = "SELECT * FROM users; DROP TABLE users; --" })
            ]),
            new ChatMessage(ChatRole.Assistant, "Done.")
        ]);

        reask.Calls.Should().Be(1, "the first message was re-asked");
        result.IsBlocked.Should().BeTrue("the tool call is evaluated even though the re-ask ended the text checks early");
        result.BlockingResult!.RuleName.Should().Be("tool-call-guardrail");
    }

    [Fact]
    public async Task GuardToolsAndReasoning_ShouldLeaveTheTextAlone()
    {
        var guard = new ChatMessageGuard(new GuardrailPolicyBuilder().RedactPii().Build());
        var message = new ChatMessage(ChatRole.Assistant,
            [new TextReasoningContent($"Mail {Email}"), new TextContent($"Mailing {Email} now.")]);

        var result = await guard.GuardToolsAndReasoningAsync([message]);

        result.WasModified.Should().BeTrue();
        result.Messages.Single().Text.Should().Be($"Mailing {Email} now.", "streamed text has already been checked");
        GuardrailChatContent.GetReasoningText(result.Messages.Single().Contents).Should().Be("Mail <EMAIL_ADDRESS>");
    }

    [Fact]
    public async Task GuardToolsAndReasoning_ShouldBlock_WhenAToolCallViolatesThePolicy()
    {
        var guard = new ChatMessageGuard(new GuardrailPolicyBuilder().GuardToolCalls().Build());
        var message = new ChatMessage(ChatRole.Assistant,
        [
            new TextContent("Reading it now."),
            new FunctionCallContent("c1", "read_file", new Dictionary<string, object?> { ["path"] = "../../../../etc/passwd" })
        ]);

        var result = await guard.GuardToolsAndReasoningAsync([message]);

        result.IsBlocked.Should().BeTrue();
        result.BlockingResult!.RuleName.Should().Be("tool-call-guardrail");
    }

    [Fact]
    public async Task ShouldExposeThePipeline_ThatRecordsToTheLedger()
    {
        var ledger = new HashChainLedger();
        var guard = new ChatMessageGuard(new GuardrailPolicyBuilder().RedactPii().Build(), ledger: ledger);

        await guard.GuardOutputAsync([new ChatMessage(ChatRole.Assistant, [new TextReasoningContent("thinking"), new TextContent("answer")])]);

        guard.Pipeline.Ledger.Should().BeSameAs(ledger);
        ledger.Count.Should().Be(2, "the answer and the reasoning are each an evaluation of their own");
    }

    [Fact]
    public async Task ShouldGiveEachOutputEvaluationTheResponseSoFar_WhenTheResponseHasToolCallsAndEarlierText()
    {
        var capture = new HistoryCapturingRule();
        var guard = new ChatMessageGuard(new GuardrailPolicyBuilder().RedactPii().AddRule(capture).Build());
        var request = new List<ChatMessage> { new(ChatRole.User, "Where is my order?") };
        var response = new List<ChatMessage>
        {
            new(ChatRole.Assistant, [new TextContent($"Checking the order for {Email}."), new FunctionCallContent("c1", "lookup_order")]),
            new(ChatRole.Tool, [new FunctionResultContent("c1", "order 42 shipped on Monday")]),
            new(ChatRole.Assistant, "Your order 42 shipped on Monday.")
        };

        await guard.GuardOutputAsync(response, request);

        var final = capture.Histories.Single(h => h.Text == "Your order 42 shipped on Monday.");
        final.Messages.Should().HaveCount(3, "the request, then the response's messages before the answer");
        final.Messages![0].Text.Should().Be("Where is my order?");
        final.Messages[1].Text.Should().Be("Checking the order for <EMAIL_ADDRESS>.", "earlier messages appear as the rules left them");
        final.Messages[2].Contents.OfType<FunctionResultContent>().Should().ContainSingle()
            .Which.Result.Should().Be("order 42 shipped on Monday");
    }

    private sealed class HistoryCapturingRule : IGuardrailRule
    {
        public List<(string Text, IReadOnlyList<ChatMessage>? Messages)> Histories { get; } = [];

        public string Name => "history-capture";

        public GuardrailPhase Phase => GuardrailPhase.Output;

        public int Order => 100;

        public ValueTask<GuardrailResult> EvaluateAsync(GuardrailContext context, CancellationToken cancellationToken = default)
        {
            lock (Histories)
                Histories.Add((context.Text, context.Messages));

            return ValueTask.FromResult(GuardrailResult.Passed());
        }
    }

    private sealed class CountingChatClient(string answer) : IChatClient
    {
        public int Calls { get; private set; }

        public Task<ChatResponse> GetResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken cancellationToken = default)
        {
            Calls++;
            return Task.FromResult(new ChatResponse(new ChatMessage(ChatRole.Assistant, answer)));
        }

        public async IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(
            IEnumerable<ChatMessage> messages, ChatOptions? options = null, [EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            var response = await GetResponseAsync(messages, options, cancellationToken);
            foreach (var update in response.ToChatResponseUpdates())
                yield return update;
        }

        public object? GetService(Type serviceType, object? serviceKey = null) => null;

        public void Dispose()
        {
        }
    }
}
