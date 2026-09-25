using System.Runtime.CompilerServices;
using AgentGuard.AgentFramework;
using FluentAssertions;
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;
using TasmanianDevil;
using TasmanianDevil.Analyzer;
using TasmanianDevil.Anonymizer.Operators;
using Xunit;

namespace AgentGuard.AgentFramework.Tests.Middleware;

// reversible redaction protects every message, and detection runs on the asynchronous path
public class PiiReversibleRedactionDetectionTests
{
    private const string Key = "0123456789abcdef"; // 128-bit

    [Fact]
    public async Task ShouldEncryptEntities_WhenDetectorIsAsyncOnly()
    {
        // a remote or Azure detector only answers on the asynchronous path
        using var engine = new PiiEngine(EncryptOptions(), extraRecognizers: [new AsyncOnlyPersonRecognizer()]);
        var (agent, received) = BuildEchoAgent(builder => builder.UsePiiReversibleRedaction(engine, Key));

        var response = await agent.RunAsync("Please call John Smith");

        received.Single().Should().NotContain("John Smith");
        response.Text.Should().Contain("John Smith", "the user sees the restored value");
    }

    [Fact]
    public async Task ShouldEncryptEntities_WhenTheyAreInAnEarlierMessage()
    {
        var (agent, received) = BuildEchoAgent(builder => builder.UsePiiReversibleRedaction(Key));

        var response = await agent.RunAsync(
        [
            new ChatMessage(ChatRole.User, "my email is john@example.com"),
            new ChatMessage(ChatRole.Assistant, "Noted, john@example.com."),
            new ChatMessage(ChatRole.User, "what's the weather?")
        ]);

        received.Should().HaveCount(3);
        received.Should().NotContain(t => t.Contains("john@example.com"));
        response.Text.Should().Contain("john@example.com");
    }

    [Fact]
    public async Task ShouldSendAnonymizedText_WhenEngineDoesNotEncrypt()
    {
        // the default engine replaces entities with tags: nothing to restore, but nothing may leak either
        using var engine = new PiiEngine();
        var (agent, received) = BuildEchoAgent(builder => builder.UsePiiReversibleRedaction(engine, Key));

        await agent.RunAsync("email me at john@example.com");

        received.Single().Should().Be("email me at <EMAIL_ADDRESS>");
    }

    [Fact]
    public async Task ShouldEncryptEntities_WhenStreamingWithAsyncOnlyDetector()
    {
        using var engine = new PiiEngine(EncryptOptions(), extraRecognizers: [new AsyncOnlyPersonRecognizer()]);
        var (agent, received) = BuildEchoAgent(builder => builder.UsePiiReversibleRedaction(engine, Key));

        var text = "";
        await foreach (var update in agent.RunStreamingAsync("Please call John Smith"))
            text += update.Text;

        received.Single().Should().NotContain("John Smith");
        text.Should().Contain("John Smith");
    }

    private static PiiOptions EncryptOptions() => new()
    {
        Operators = new Dictionary<string, OperatorConfig>
        {
            ["DEFAULT"] = new("encrypt", new Dictionary<string, object> { [OperatorParams.Key] = Key })
        }
    };

    // echoes every message it receives, so tokens come back for restoration
    private static (AIAgent Agent, List<string> Received) BuildEchoAgent(Func<AIAgentBuilder, AIAgentBuilder> configure)
    {
        var received = new List<string>();
        var inner = new TestAgent(
            (messages, _, _, _) =>
            {
                var texts = messages.Select(m => m.Text).ToList();
                received.AddRange(texts);
                return Task.FromResult(new AgentResponse(new ChatMessage(ChatRole.Assistant, $"You said: {string.Join(" | ", texts)}")));
            },
            (messages, _, _, ct) =>
            {
                var texts = messages.Select(m => m.Text).ToList();
                received.AddRange(texts);
                return Echo($"You said: {string.Join(" | ", texts)}", ct);
            });

        return (configure(inner.AsBuilder()).Build(null!), received);
    }

    private static async IAsyncEnumerable<AgentResponseUpdate> Echo(string text, [EnumeratorCancellation] CancellationToken ct = default)
    {
        await Task.Yield();
        ct.ThrowIfCancellationRequested();
        yield return new AgentResponseUpdate(ChatRole.Assistant, text);
    }

    private sealed class AsyncOnlyPersonRecognizer() : EntityRecognizer(["PERSON"], "async-person")
    {
        public override bool RequiresAsync => true;

        public override IReadOnlyList<RecognizerResult> Analyze(string text, IReadOnlyList<string> entities) => [];

        public override ValueTask<IReadOnlyList<RecognizerResult>> AnalyzeAsync(
            string text, IReadOnlyList<string> entities, CancellationToken ct = default)
        {
            var index = text.IndexOf("John Smith", StringComparison.Ordinal);
            return new(index < 0 ? [] : [new RecognizerResult("PERSON", index, index + "John Smith".Length, 0.9)]);
        }
    }
}
