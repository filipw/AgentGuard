using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Text.RegularExpressions;
using AgentGuard.AgentFramework;
using AgentGuard.Core.Builders;
using AgentGuard.Core.Guardrails;
using FluentAssertions;
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;
using Xunit;

namespace AgentGuard.AgentFramework.Tests.Middleware;

// tools are the caller's own code: a tool is called with the values the model's tokens stand for, and what
// it returns is encrypted before the model sees it, with tokens the response can be restored from
public partial class PiiReversibleRedactionToolTests
{
    private const string Key = "0123456789abcdef";
    private const string Email = "john@example.com";
    private const string ToolEmail = "jane@example.com";
    private const string Request = $"send a note to {Email}";

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ShouldCallTheToolWithTheOriginalValue_WhenModelPassesATokenAsAnArgument(bool streaming)
    {
        var received = new List<string>();
        var tool = AIFunctionFactory.Create((string email) => { received.Add(email); return "sent"; }, "send_note");
        var (agent, model) = BuildAgent(
            (messages, call) => call == 0
                ? Call("c1", "send_note", new() { ["email"] = TokenIn(LastUserText(messages)) })
                : Answer("Done."),
            tool);
        var session = await agent.CreateSessionAsync();

        var answer = await RunAsync(agent, Request, session, streaming);

        received.Should().Equal(Email);
        answer.Should().Be("Done.");
        model.Calls.Should().OnlyContain(call => !SeenByModel(call).Contains(Email), "the call the model made keeps its token");
        SeenByModel(History(agent, session)).Should().NotContain(Email, "the saved call keeps its token too");
    }

    [Fact]
    public async Task ShouldRestoreTokensInsideNestedArguments()
    {
        AIFunctionArguments? received = null;
        var tool = new RawFunction("send_note", arguments => { received = arguments; return "sent"; });
        var (agent, _) = BuildAgent(
            (messages, call) =>
            {
                if (call > 0)
                    return Answer("Done.");

                var token = TokenIn(LastUserText(messages));
                return Call("c1", "send_note", new()
                {
                    ["recipient"] = Json($$"""{ "address": "{{token}}", "cc": ["{{token}}", 7], "note": "for {{token}} only", "priority": 2 }"""),
                    ["subject"] = Json($"\"about {token}\""),
                    ["tags"] = new List<object?> { token, 5, null },
                    ["meta"] = new Dictionary<string, object?> { ["owner"] = token, ["copies"] = new object?[] { token } },
                    ["retries"] = 3
                });
            },
            tool);

        await agent.RunAsync(Request);

        received.Should().NotBeNull();
        var recipient = received!["recipient"].Should().BeOfType<JsonElement>().Subject;
        recipient.GetProperty("address").GetString().Should().Be(Email);
        recipient.GetProperty("cc")[0].GetString().Should().Be(Email);
        recipient.GetProperty("cc")[1].GetInt32().Should().Be(7);
        recipient.GetProperty("note").GetString().Should().Be($"for {Email} only");
        recipient.GetProperty("priority").GetInt32().Should().Be(2);
        received["subject"].Should().BeOfType<JsonElement>().Which.GetString().Should().Be($"about {Email}");
        received["tags"].Should().BeAssignableTo<IEnumerable<object?>>().Which.Should().Equal(Email, 5, null);
        var meta = received["meta"].Should().BeAssignableTo<IDictionary<string, object?>>().Subject;
        meta["owner"].Should().Be(Email);
        meta["copies"].Should().BeAssignableTo<IEnumerable<object?>>().Which.Should().Equal(Email);
        received["retries"].Should().Be(3);
    }

    [Fact]
    public async Task ShouldPassArgumentsOnAsTheyAre_WhenTheyHoldNoToken()
    {
        AIFunctionArguments? received = null;
        var city = Json("""{ "name": "Oslo" }""");
        var tool = new RawFunction("get_weather", arguments => { received = arguments; return "sunny"; });
        var (agent, _) = BuildAgent(
            (_, call) => call == 0 ? Call("c1", "get_weather", new() { ["city"] = city, ["unit"] = "C" }) : Answer("Sunny."),
            tool);

        await agent.RunAsync(Request);

        received.Should().NotBeNull();
        received!["city"].Should().BeOfType<JsonElement>().Which.GetRawText().Should().Be(city.GetRawText());
        received["unit"].Should().Be("C");
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ShouldEncryptAToolResult_AndRestoreItsTokensInTheAnswer(bool streaming)
    {
        var tool = AIFunctionFactory.Create(() => $"The account manager is reachable at {ToolEmail}.", "lookup_manager");
        var (agent, model) = BuildAgent(
            (messages, call) => call == 0
                ? Call("c1", "lookup_manager", [])
                : Answer($"Write to {TokenIn(FedToolResult(messages))}."),
            tool);

        var answer = await RunAsync(agent, "who is my account manager?", session: null, streaming);

        FedToolResult(model.Calls[1]).Should().NotContain(ToolEmail, "the model only ever sees the token")
            .And.StartWith("The account manager is reachable at ");
        answer.Should().Be($"Write to {ToolEmail}.");
    }

    [Fact]
    public async Task ShouldKeepAJsonToolResultJson_WhenItsValuesAreEncrypted()
    {
        var tool = AIFunctionFactory.Create(() => new Customer(42, ToolEmail), "lookup_customer");
        var (agent, model) = BuildAgent(
            (messages, call) => call == 0
                ? Call("c1", "lookup_customer", [])
                : Answer($"Their email is {TokenIn(FedToolResult(messages))}."),
            tool);

        var response = await agent.RunAsync("who is customer 42?");

        var fed = FunctionResult(model.Calls[1]).Result.Should().BeOfType<JsonElement>().Subject;
        fed.ValueKind.Should().Be(JsonValueKind.Object);
        fed.GetProperty("id").GetInt32().Should().Be(42);
        TokenPattern().IsMatch(fed.GetProperty("email").GetString()!).Should().BeTrue();
        fed.GetRawText().Should().NotContain(ToolEmail);
        response.Text.Should().Be($"Their email is {ToolEmail}.");
    }

    [Fact]
    public async Task ShouldEncryptAToolResult_WhenTheToolReturnsAnObjectOfItsOwn()
    {
        // not made by AIFunctionFactory, so the object reaches the function-invoking client as it is
        var tool = new RawFunction("lookup_customer", _ => new Customer(42, ToolEmail));
        var (agent, model) = BuildAgent((_, call) => call == 0 ? Call("c1", "lookup_customer", []) : Answer("Found."), tool);

        await agent.RunAsync("who is customer 42?");

        var fed = FunctionResult(model.Calls[1]).Result.Should().BeOfType<JsonElement>().Subject;
        fed.GetProperty("id").GetInt32().Should().Be(42);
        fed.GetRawText().Should().NotContain(ToolEmail);
    }

    [Fact]
    public async Task ShouldEncryptOnlyTheText_WhenAToolResultMixesTextAndOtherContent()
    {
        var photo = new DataContent(new byte[] { 1, 2, 3 }, "image/png");
        var tool = new RawFunction("lookup_manager", _ => new List<AIContent> { new TextContent($"Reach her at {ToolEmail}."), photo });
        var (agent, model) = BuildAgent((_, call) => call == 0 ? Call("c1", "lookup_manager", []) : Answer("Found."), tool);

        await agent.RunAsync("who is my account manager?");

        var fed = FunctionResult(model.Calls[1]).Result.Should().BeAssignableTo<IEnumerable<AIContent>>().Subject.ToList();
        fed.Should().HaveCount(2);
        fed[0].Should().BeOfType<TextContent>().Which.Text.Should().StartWith("Reach her at ").And.NotContain(ToolEmail);
        fed[1].Should().BeSameAs(photo);
    }

    [Fact]
    public async Task ShouldPassAToolResultOnAsItIs_WhenItHoldsNoPii()
    {
        var tool = AIFunctionFactory.Create(() => new Forecast("Oslo", 12), "get_weather");
        var (agent, model) = BuildAgent((_, call) => call == 0 ? Call("c1", "get_weather", []) : Answer("Mild."), tool);

        await agent.RunAsync("how is the weather?");

        var fed = FunctionResult(model.Calls[1]).Result.Should().BeOfType<JsonElement>().Subject;
        fed.GetProperty("city").GetString().Should().Be("Oslo");
        fed.GetProperty("degrees").GetInt32().Should().Be(12);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ShouldCallTheNextToolWithTheOriginalValue_WhenModelPassesOnATokenFromAToolResult(bool streaming)
    {
        var received = new List<string>();
        var lookup = AIFunctionFactory.Create(() => $"Her address is {ToolEmail}.", "lookup_manager");
        var send = AIFunctionFactory.Create((string email) => { received.Add(email); return "sent"; }, "send_note");
        var (agent, model) = BuildAgent(
            (messages, call) => call switch
            {
                0 => Call("c1", "lookup_manager", []),
                1 => Call("c2", "send_note", new() { ["email"] = TokenIn(FedToolResult(messages)) }),
                _ => Answer("Done.")
            },
            lookup,
            send);

        await RunAsync(agent, "send my account manager a note", session: null, streaming);

        received.Should().Equal(ToolEmail);
        model.Calls.Should().OnlyContain(call => !SeenByModel(call).Contains(ToolEmail));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ShouldRestoreAToolResultToken_WhenALaterTurnOfTheSessionRecallsIt(bool streaming)
    {
        var tool = AIFunctionFactory.Create(() => $"Her address is {ToolEmail}.", "lookup_manager");
        var (agent, model) = BuildAgent(
            (messages, call) => call switch
            {
                0 => Call("c1", "lookup_manager", []),
                1 => Answer("Found her."),
                _ => Answer($"It is {TokenIn(FedToolResult(messages))}.")
            },
            tool);
        var session = await agent.CreateSessionAsync();

        await RunAsync(agent, "who is my account manager?", session, streaming);
        var serialized = await agent.SerializeSessionAsync(session);
        var answer = await RunAsync(agent, "what was her address?", await agent.DeserializeSessionAsync(serialized), streaming);

        serialized.GetRawText().Should().NotContain(ToolEmail, "the session keeps the result as the model saw it");
        SeenByModel(model.Calls[2]).Should().NotContain(ToolEmail);
        answer.Should().Be($"It is {ToolEmail}.");
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ShouldRestoreTheTokensOfEveryToolResult_WhenToolsRunConcurrently(bool streaming)
    {
        const int Tools = 12;

        // every tool waits until all of them are running, so their results are encrypted at the same time
        var running = 0;
        var allRunning = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var tool = AIFunctionFactory.Create(
            async (int id) =>
            {
                if (Interlocked.Increment(ref running) == Tools)
                    allRunning.SetResult();

                await allRunning.Task.WaitAsync(TimeSpan.FromSeconds(30));
                return $"user{id}@example.com";
            },
            "lookup_email");

        var model = new ScriptedChatClient((messages, call) => call == 0
            ? new ChatResponse(new ChatMessage(ChatRole.Assistant,
                [.. Enumerable.Range(0, Tools).Select(id => new FunctionCallContent($"c{id}", "lookup_email", new Dictionary<string, object?> { ["id"] = id }))]))
            : Answer(string.Join(' ', FunctionResults(messages).Select(result => GuardrailChatContent.ToText(result.Result)))));
        var client = new ChatClientBuilder(model).UseFunctionInvocation(configure: c => c.AllowConcurrentInvocation = true).Build();
        var agent = client.AsAIAgent(instructions: "a", name: "a", tools: [tool]).AsBuilder().UsePiiReversibleRedaction(Key).Build();
        var session = await agent.CreateSessionAsync();

        var answer = await RunAsync(agent, "look everyone up", session, streaming);

        SeenByModel(model.Calls[1]).Should().NotContain("@example.com");
        answer.Split(' ').Should().BeEquivalentTo(Enumerable.Range(0, Tools).Select(id => $"user{id}@example.com"));
        PiiTokenRegistry.Read(session).Should().HaveCount(Tools, "a later turn needs every one of them");
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ShouldProtectTools_WhenToolGuardrailsInterceptThemToo(bool guardrailsFirst)
    {
        var received = new List<string>();
        var tool = AIFunctionFactory.Create((string email) => { received.Add(email); return $"Copied {ToolEmail}."; }, "send_note");
        var model = new ScriptedChatClient((messages, call) => call == 0
            ? Call("c1", "send_note", new() { ["email"] = TokenIn(LastUserText(messages)) })
            : Answer($"Sent, with a copy to {TokenIn(FedToolResult(messages))}."));
        var policy = new GuardrailPolicyBuilder().GuardToolCalls().GuardToolResults().Build();
        var builder = model.AsAIAgent(instructions: "a", name: "a", tools: [tool]).AsBuilder();
        var agent = (guardrailsFirst
            ? builder.UseAgentGuard(policy).UsePiiReversibleRedaction(Key)
            : builder.UsePiiReversibleRedaction(Key).UseAgentGuard(policy)).Build();

        var response = await agent.RunAsync(Request);

        received.Should().Equal(Email);
        model.Calls.Should().OnlyContain(call => !SeenByModel(call).Contains(Email) && !SeenByModel(call).Contains(ToolEmail));
        response.Text.Should().Be($"Sent, with a copy to {ToolEmail}.");
    }

    [Fact]
    public async Task ShouldRestoreTokensInReasoning_WhenResponseHasReasoning()
    {
        var protectedData = "opaque-reasoning-state";
        var agent = new TestAgent(
            (messages, _, _, _) =>
            {
                var token = TokenIn(messages.Last().Text);
                return Task.FromResult(new AgentResponse(new ChatMessage(ChatRole.Assistant,
                [
                    new TextReasoningContent($"The user wants a note sent to {token}.") { ProtectedData = protectedData },
                    new TextContent($"Sending it to {token}.")
                ])));
            },
            (_, _, _, _) => throw new NotSupportedException())
            .AsBuilder()
            .UsePiiReversibleRedaction(Key)
            .Build(null!);

        var response = await agent.RunAsync(Request);

        var message = response.Messages.Should().ContainSingle().Subject;
        var reasoning = message.Contents.OfType<TextReasoningContent>().Should().ContainSingle().Subject;
        reasoning.Text.Should().Be($"The user wants a note sent to {Email}.");
        reasoning.ProtectedData.Should().Be(protectedData);
        message.Text.Should().Be($"Sending it to {Email}.");
    }

    [Theory]
    [InlineData(1)]
    [InlineData(7)]
    [InlineData(1000)]
    public async Task ShouldRestoreTokensInStreamedReasoning_WhenStreamSplitsThem(int chunkSize)
    {
        var agent = new TestAgent(
            (_, _, _, _) => throw new NotSupportedException(),
            (messages, _, _, ct) =>
            {
                var token = TokenIn(messages.Last().Text);
                return Stream(
                [
                    .. Chunk($"The user wants a note sent to {token}", chunkSize)
                        .Select(piece => new AgentResponseUpdate(ChatRole.Assistant, [new TextReasoningContent(piece)]) { MessageId = "m1" }),
                    .. Chunk($"Sending it to {token}.", chunkSize)
                        .Select(piece => new AgentResponseUpdate(ChatRole.Assistant, piece) { MessageId = "m1" })
                ], ct);
            })
            .AsBuilder()
            .UsePiiReversibleRedaction(Key)
            .Build(null!);

        var updates = new List<AgentResponseUpdate>();
        await foreach (var update in agent.RunStreamingAsync(Request))
            updates.Add(update);

        string.Concat(updates.Select(u => GuardrailChatContent.GetReasoningText(u.Contents)))
            .Should().Be($"The user wants a note sent to {Email}");
        string.Concat(updates.Select(u => u.Text)).Should().Be($"Sending it to {Email}.");

        // the reasoning is complete before the answer begins, as it was in the stream
        var contents = updates.SelectMany(u => u.Contents).Where(c => c is TextContent or TextReasoningContent).ToList();
        contents.SkipWhile(c => c is TextReasoningContent).Should().AllBeOfType<TextContent>();
        updates.ToAgentResponse().Messages.Should().ContainSingle();
    }

    private sealed record Customer(int Id, string Email);

    private sealed record Forecast(string City, int Degrees);

    // a chat client agent with tools over a model that answers each call with script(messages, call)
    private static (AIAgent Agent, ScriptedChatClient Model) BuildAgent(
        Func<IReadOnlyList<ChatMessage>, int, ChatResponse> script, params AITool[] tools)
    {
        var model = new ScriptedChatClient(script);
        var agent = model.AsAIAgent(instructions: "a", name: "a", tools: tools).AsBuilder().UsePiiReversibleRedaction(Key).Build();
        return (agent, model);
    }

    private static ChatResponse Call(string callId, string name, Dictionary<string, object?> arguments) =>
        new(new ChatMessage(ChatRole.Assistant, [new FunctionCallContent(callId, name, arguments)]));

    private static ChatResponse Answer(string text) => new(new ChatMessage(ChatRole.Assistant, text));

    private static JsonElement Json(string json)
    {
        using var document = JsonDocument.Parse(json);
        return document.RootElement.Clone();
    }

    private static string LastUserText(IEnumerable<ChatMessage> messages) => messages.Last(m => m.Role == ChatRole.User).Text;

    private static IEnumerable<FunctionResultContent> FunctionResults(IEnumerable<ChatMessage> messages) =>
        messages.SelectMany(m => m.Contents).OfType<FunctionResultContent>();

    private static FunctionResultContent FunctionResult(IEnumerable<ChatMessage> messages) => FunctionResults(messages).Single();

    // the tool result the model was given, as text
    private static string FedToolResult(IEnumerable<ChatMessage> messages) => GuardrailChatContent.ToText(FunctionResult(messages).Result);

    // everything in the messages a model reads: text, reasoning, tool call arguments and tool results
    private static string SeenByModel(IEnumerable<ChatMessage> messages) =>
        string.Join('\n', messages.SelectMany(m => m.Contents).Select(content => content switch
        {
            TextContent text => text.Text,
            TextReasoningContent reasoning => reasoning.Text,
            FunctionCallContent call => string.Join('\n', (call.Arguments ?? new Dictionary<string, object?>()).Values.Select(GuardrailChatContent.ToText)),
            FunctionResultContent result => GuardrailChatContent.ToText(result.Result),
            _ => ""
        }));

    private static List<ChatMessage> History(AIAgent agent, AgentSession session) =>
        agent.GetService<InMemoryChatHistoryProvider>()!.GetMessages(session);

    [GeneratedRegex("A[Q-Za-f][A-Za-z0-9_-]{37,}")]
    private static partial Regex TokenPattern();

    private static string TokenIn(string text) =>
        TokenPattern().Match(text) is { Success: true } match ? match.Value : throw new InvalidOperationException($"no token in '{text}'");

    private static IEnumerable<string> Chunk(string text, int size)
    {
        for (var i = 0; i < text.Length; i += size)
            yield return text.Substring(i, Math.Min(size, text.Length - i));
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

    private static async Task<string> RunAsync(AIAgent agent, string message, AgentSession? session, bool streaming)
    {
        if (!streaming)
            return (await agent.RunAsync(message, session)).Text;

        // the answer is the text of the last message; a streamed run also carries the tool-calling steps
        var updates = new List<AgentResponseUpdate>();
        await foreach (var update in agent.RunStreamingAsync(message, session))
            updates.Add(update);

        return updates.ToAgentResponse().Text;
    }

    // a tool that is handed its arguments as they are and returns its result as it is
    private sealed class RawFunction(string name, Func<AIFunctionArguments, object?> invoke) : AIFunction
    {
        public override string Name => name;

        public override string Description => name;

        protected override ValueTask<object?> InvokeCoreAsync(AIFunctionArguments arguments, CancellationToken cancellationToken) =>
            ValueTask.FromResult(invoke(arguments));
    }
}
