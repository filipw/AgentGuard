// AgentGuard - PII in Microsoft Agent Framework (MAF)
// Shows the three ways PII is handled around a MAF agent:
//   [1] Standard redaction      - PiiRule via .UseAgentGuard(): the model sees redacted input,
//                                  and PII in the model's reply is scrubbed before the user sees it.
//   [2] Reversible redaction     - .UsePiiReversibleRedaction(): PII is encrypted before the model
//                                  (and provider) ever see it, then decrypted back in the response,
//                                  so the model reasons over opaque tokens but the user sees the
//                                  real values. This is the cross-phase round-trip a single rule
//                                  cannot express.
//   [3] Tool-result redaction    - PiiRule runs in the tool-result lane (.GuardToolResults()), so PII
//                                  returned by a tool is scrubbed before it is fed back to the LLM.
//
// Parts [1] and [2] run fully offline against a scripted stub agent (deterministic, no LLM needed).
// Part [3] needs a real function-calling model; set OPENAI_BASE_URL / OPENAI_MODEL to run it.

using System.ClientModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Text.Json;
using AgentGuard.AgentFramework;
using AgentGuard.Core.Builders;
using AgentGuard.Pii;
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;
using OpenAI;

const string piiKey = "0123456789abcdef"; // 128-bit AES key for reversible redaction

Console.WriteLine("AgentGuard - PII in Agent Framework");
Console.WriteLine(new string('=', 64));

// ─── [1] Standard redaction (input + output) ──────────────────────────────
Console.WriteLine("\n[1] Standard redaction (.UseAgentGuard(g => g.RedactPii()))");
Console.WriteLine(new string('-', 64));

string? modelSawInput = null;
var redactingAgent = new ScriptedAgent(messages =>
    {
        modelSawInput = messages[^1].Text;
        // the assistant reply itself contains PII, to show output-side redaction
        return "Thanks - a confirmation was emailed to advisor@bank.com.";
    })
    .AsBuilder()
    .UseAgentGuard(g => g.RedactPii())
    .Build(null!);

const string input1 = "I'm Jane Doe, my email is jane@acme.com and my card is 4012888888881881.";
var reply1 = await redactingAgent.RunAsync(input1, null, null, CancellationToken.None);

Console.WriteLine($"  user typed     : {input1}");
Console.WriteLine($"  model received : {modelSawInput}");
Console.WriteLine($"  user sees back : {reply1.Messages[^1].Text}");

// ─── [2] Reversible redaction (encrypt in, decrypt out) ───────────────────
Console.WriteLine("\n[2] Reversible redaction (.UsePiiReversibleRedaction(key))");
Console.WriteLine(new string('-', 64));

string? modelSawReversible = null;
var reversibleAgent = new ScriptedAgent(messages =>
    {
        modelSawReversible = messages[^1].Text;
        // a model that quotes the request back echoes the opaque tokens verbatim
        return $"Got it. I'll follow up on: \"{messages[^1].Text}\"";
    })
    .AsBuilder()
    .UsePiiReversibleRedaction(piiKey)
    .Build(null!);

const string input2 = "Email me at john@example.com about order 12345.";
var reply2 = await reversibleAgent.RunAsync(input2, null, null, CancellationToken.None);

Console.WriteLine($"  user typed     : {input2}");
Console.WriteLine($"  model received : {modelSawReversible}");
Console.WriteLine($"  user sees back : {reply2.Messages[^1].Text}");
Console.WriteLine("  (the email never reached the model; it was decrypted only on the way out)");

// ─── [3] Tool-result redaction (needs a real function-calling model) ──────
Console.WriteLine("\n[3] Tool-result redaction (.GuardToolResults() + .RedactPii())");
Console.WriteLine(new string('-', 64));

var endpoint = Environment.GetEnvironmentVariable("OPENAI_BASE_URL");
var model = Environment.GetEnvironmentVariable("OPENAI_MODEL");
var apiKey = Environment.GetEnvironmentVariable("OPENAI_API_KEY") ?? "unused";

if (string.IsNullOrEmpty(endpoint) || string.IsNullOrEmpty(model))
{
    Console.WriteLine("  skipped - set OPENAI_BASE_URL and OPENAI_MODEL to run the tool-calling demo.");
    Console.WriteLine("  With them set, the lookup_customer tool below returns a record full of PII;");
    Console.WriteLine("  PiiRule (order 20, in the default tool-result lane) scrubs it before the LLM reads it.");
}
else
{
    var chatClient = new OpenAIClient(new ApiKeyCredential(apiKey), new OpenAIClientOptions { Endpoint = new Uri(endpoint) })
        .GetChatClient(model)   
        .AsIChatClient();

    // a tool that returns a customer record laden with PII (email, phone, SSN)
    [Description("Look up a customer record by name.")]
    static string LookupCustomer([Description("The customer name")] string name)
    {
        Console.WriteLine($"    [tool executed] lookup_customer(name: {name}) -> returning raw PII record");
        return JsonSerializer.Serialize(new
        {
            name,
            email = "jane.doe@example.com",
            phone = "+1 415 555 0132",
            ssn = "078-05-1120",
        });
    }

    var policy = new GuardrailPolicyBuilder()
        .RedactPii()         // order 20 - runs on tool results too
        .GuardToolResults()  // wires the tool-result interception
        .Build();

    var toolAgent = chatClient
        .AsAIAgent(
            instructions: "You are a support agent. Use lookup_customer when asked about a customer.",
            name: "SupportBot",
            tools: [AIFunctionFactory.Create(LookupCustomer)])
        .AsBuilder()
        .UseAgentGuard(policy)
        .Build();

    Console.WriteLine("  user: Look up the customer Jane Doe and summarize her contact info.");
    var toolReply = await toolAgent.RunAsync("Look up the customer Jane Doe and summarize her contact info.");
    Console.WriteLine($"  response: {toolReply}");
    Console.WriteLine("  (the model only ever saw <EMAIL_ADDRESS>/<PHONE_NUMBER>/<US_SSN>, not the real values)");
}

Console.WriteLine($"\n{new string('=', 64)}\nDone.");
return 0;

/// <summary>
/// A minimal scripted <see cref="AIAgent"/> for offline demos: replies with the text produced by the
/// supplied function (which receives the messages the agent was invoked with, after input guardrails).
/// </summary>
internal sealed class ScriptedAgent(Func<IReadOnlyList<ChatMessage>, string> reply) : AIAgent
{
    protected override Task<AgentResponse> RunCoreAsync(
        IEnumerable<ChatMessage> messages, AgentSession? session, AgentRunOptions? options, CancellationToken ct)
    {
        var text = reply(messages as IReadOnlyList<ChatMessage> ?? messages.ToList());
        return Task.FromResult(new AgentResponse(new ChatMessage(ChatRole.Assistant, text)));
    }

    protected override async IAsyncEnumerable<AgentResponseUpdate> RunCoreStreamingAsync(
        IEnumerable<ChatMessage> messages, AgentSession? session, AgentRunOptions? options,
        [EnumeratorCancellation] CancellationToken ct = default)
    {
        await Task.Yield();
        yield return new AgentResponseUpdate(ChatRole.Assistant, reply(messages as IReadOnlyList<ChatMessage> ?? messages.ToList()));
    }

    protected override ValueTask<AgentSession> CreateSessionCoreAsync(CancellationToken ct)
        => throw new NotSupportedException();

    protected override ValueTask<JsonElement> SerializeSessionCoreAsync(
        AgentSession session, JsonSerializerOptions? options, CancellationToken ct)
        => throw new NotSupportedException();

    protected override ValueTask<AgentSession> DeserializeSessionCoreAsync(
        JsonElement state, JsonSerializerOptions? options, CancellationToken ct)
        => throw new NotSupportedException();
}
