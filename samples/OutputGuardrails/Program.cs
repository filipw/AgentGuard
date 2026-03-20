// AgentGuard — Output Guardrails Sample
// Demonstrates LLM-based output validation: policy enforcement, groundedness checking, and copyright detection.
// These rules run on agent responses (output phase) to catch violations before they reach the user.
//
// NOTE: This sample uses a mock IChatClient to simulate LLM responses.
// In production, replace MockChatClient with a real IChatClient (e.g., from Microsoft.Extensions.AI.OpenAI).

using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Builders;
using AgentGuard.Core.Guardrails;
using AgentGuard.Core.Rules.LLM;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.Logging.Abstractions;

Console.WriteLine("AgentGuard — Output Guardrails Demo");
Console.WriteLine(new string('=', 60));

// ─── Example 1: Output Policy Enforcement ───────────────────────────────
// Block responses that recommend competitor products.

Console.WriteLine("\n[1] Output Policy Enforcement");
Console.WriteLine(new string('─', 60));

var policyClient = new MockChatClient(response =>
{
    if (response.Contains("CompetitorCRM", StringComparison.OrdinalIgnoreCase))
        return "VIOLATION|reason:Response recommends competitor product CompetitorCRM";
    return "COMPLIANT";
});

var policyPipeline = new GuardrailPipeline(
    new GuardrailPolicyBuilder("output-policy-demo")
        .EnforceOutputPolicy(policyClient, "Never recommend competitor products. Our product is AgentCRM.")
        .Build(),
    NullLogger<GuardrailPipeline>.Instance);

var policyScenarios = new (string Label, string Response)[]
{
    ("Compliant", "AgentCRM offers great reporting features. You can generate custom dashboards from the Analytics tab."),
    ("Violation", "You might want to try CompetitorCRM — they have a better pricing tier for small teams."),
    ("Compliant", "Our support team can help you migrate your data. Contact us at support@agentcrm.com."),
};

foreach (var (label, response) in policyScenarios)
{
    Console.WriteLine($"\n  [{label}] \"{response[..Math.Min(80, response.Length)]}...\"");
    var ctx = new GuardrailContext { Text = response, Phase = GuardrailPhase.Output };
    var result = await policyPipeline.RunAsync(ctx);
    PrintResult(result);
}

// ─── Example 2: Groundedness Checking ───────────────────────────────────
// Detect hallucinated facts not supported by conversation context.

Console.WriteLine($"\n\n[2] Groundedness Checking");
Console.WriteLine(new string('─', 60));

var groundednessClient = new MockChatClient(response =>
{
    if (response.Contains("47%", StringComparison.OrdinalIgnoreCase)
        || response.Contains("founded in 1987", StringComparison.OrdinalIgnoreCase))
        return "UNGROUNDED|claim:Fabricated specific statistics and founding date not present in conversation";
    return "GROUNDED";
});

var groundednessPipeline = new GuardrailPipeline(
    new GuardrailPolicyBuilder("groundedness-demo")
        .CheckGroundedness(groundednessClient)
        .Build(),
    NullLogger<GuardrailPipeline>.Instance);

// Simulate a conversation where user asked about their account
var conversationHistory = new List<ChatMessage>
{
    new(ChatRole.User, "What's the status of my order #12345?"),
    new(ChatRole.Assistant, "Your order #12345 was shipped on March 15th via FedEx. The tracking number is FX-9876543."),
    new(ChatRole.User, "When will it arrive?"),
};

var groundednessScenarios = new (string Label, string Response)[]
{
    ("Grounded", "Based on the FedEx tracking for your order #12345, standard delivery typically takes 3-5 business days from the ship date of March 15th."),
    ("Hallucinated", "Your order #12345 is being handled by our warehouse team, which was founded in 1987 and has a 47% faster processing rate than industry average."),
    ("Grounded", "Your order #12345 shipped on March 15th. You can track it with FedEx using tracking number FX-9876543."),
};

foreach (var (label, response) in groundednessScenarios)
{
    Console.WriteLine($"\n  [{label}] \"{response[..Math.Min(80, response.Length)]}...\"");
    var ctx = new GuardrailContext
    {
        Text = response,
        Phase = GuardrailPhase.Output,
        Messages = conversationHistory
    };
    var result = await groundednessPipeline.RunAsync(ctx);
    PrintResult(result);
}

// ─── Example 3: Copyright Detection ─────────────────────────────────────
// Detect verbatim reproduction of copyrighted material.

Console.WriteLine($"\n\n[3] Copyright Detection");
Console.WriteLine(new string('─', 60));

var copyrightClient = new MockChatClient(response =>
{
    if (response.Contains("Here are the full lyrics", StringComparison.OrdinalIgnoreCase))
        return "COPYRIGHT|source:Famous Song by Popular Artist|type:lyrics";
    return "CLEAN";
});

var copyrightPipeline = new GuardrailPipeline(
    new GuardrailPolicyBuilder("copyright-demo")
        .CheckCopyright(copyrightClient)
        .Build(),
    NullLogger<GuardrailPipeline>.Instance);

var copyrightScenarios = new (string Label, string Response)[]
{
    ("Original", "Here's a summary of the song: it explores themes of resilience and hope, with a powerful chorus that builds momentum."),
    ("Copyright", "Here are the full lyrics to the song:\n\nVerse 1: Walking through the shadows of the night...\nChorus: We rise above, we shine so bright..."),
    ("Short quote", "As the song goes, \"we rise above\" — a powerful message about perseverance."),
};

foreach (var (label, response) in copyrightScenarios)
{
    var display = response.Replace("\n", " ");
    Console.WriteLine($"\n  [{label}] \"{display[..Math.Min(80, display.Length)]}...\"");
    var ctx = new GuardrailContext { Text = response, Phase = GuardrailPhase.Output };
    var result = await copyrightPipeline.RunAsync(ctx);
    PrintResult(result);
}

// ─── Example 4: Combined Output Pipeline ────────────────────────────────
// All three output rules in a single pipeline — rules execute in order.

Console.WriteLine($"\n\n[4] Combined Output Pipeline (Policy + Groundedness + Copyright)");
Console.WriteLine(new string('─', 60));

var combinedPipeline = new GuardrailPipeline(
    new GuardrailPolicyBuilder("combined-output")
        .EnforceOutputPolicy(policyClient, "Never recommend competitor products. Our product is AgentCRM.")
        .CheckGroundedness(groundednessClient)
        .CheckCopyright(copyrightClient)
        .Build(),
    NullLogger<GuardrailPipeline>.Instance);

var combinedScenarios = new (string Label, string Response)[]
{
    ("Clean", "Your order shipped on March 15th. You can track it using the FedEx link in your confirmation email."),
    ("Policy violation", "Have you considered switching to CompetitorCRM? Their free tier is quite generous."),
    ("Hallucinated", "Our company, founded in 1987, processes orders 47% faster than any other provider."),
};

foreach (var (label, response) in combinedScenarios)
{
    Console.WriteLine($"\n  [{label}] \"{response[..Math.Min(80, response.Length)]}...\"");
    var ctx = new GuardrailContext
    {
        Text = response,
        Phase = GuardrailPhase.Output,
        Messages = conversationHistory
    };
    var result = await combinedPipeline.RunAsync(ctx);
    PrintResult(result);
}

// ─── Example 5: Warn Mode ───────────────────────────────────────────────
// Instead of blocking, attach metadata warnings for downstream handling.

Console.WriteLine($"\n\n[5] Warn Mode (non-blocking with metadata)");
Console.WriteLine(new string('─', 60));

var warnPipeline = new GuardrailPipeline(
    new GuardrailPolicyBuilder("warn-mode-demo")
        .EnforceOutputPolicy(policyClient, "Never recommend competitor products.", OutputPolicyAction.Warn)
        .CheckGroundedness(groundednessClient, new LlmGroundednessOptions { Action = GroundednessAction.Warn })
        .Build(),
    NullLogger<GuardrailPipeline>.Instance);

var warnResponse = "Have you considered CompetitorCRM? Their support is excellent.";
Console.WriteLine($"\n  Input: \"{warnResponse}\"");
var warnCtx = new GuardrailContext { Text = warnResponse, Phase = GuardrailPhase.Output, Messages = conversationHistory };
var warnResult = await warnPipeline.RunAsync(warnCtx);

Console.WriteLine($"  Blocked: {warnResult.IsBlocked}");
Console.WriteLine($"  Response passes through (warn mode), but metadata is attached:");
// In warn mode, individual rule results carry metadata
foreach (var ruleResult in warnResult.AllResults)
{
    if (ruleResult.Metadata?.Count > 0)
    {
        Console.WriteLine($"    Rule '{ruleResult.RuleName}':");
        foreach (var kv in ruleResult.Metadata)
            Console.WriteLine($"      {kv.Key}: {kv.Value}");
    }
}

Console.WriteLine($"\n{new string('=', 60)}");
Console.WriteLine("Done. In production, replace MockChatClient with a real IChatClient.");

// ─── Helpers ─────────────────────────────────────────────────────────────

static void PrintResult(GuardrailPipelineResult result)
{
    if (result.IsBlocked)
    {
        Console.WriteLine($"  BLOCKED by '{result.BlockingResult!.RuleName}': {result.BlockingResult.Reason}");
        if (result.BlockingResult.Metadata is { } meta)
        {
            foreach (var kv in meta)
                Console.WriteLine($"    {kv.Key}: {kv.Value}");
        }
    }
    else
    {
        Console.WriteLine("  PASSED all output guardrails");
    }
}

// ─── Mock IChatClient ────────────────────────────────────────────────────
// Simulates an LLM judge by matching keywords in the input text.
// Replace with a real IChatClient for production use.

sealed class MockChatClient : IChatClient
{
    private readonly Func<string, string> _respond;

    public MockChatClient(Func<string, string> respond) => _respond = respond;

    public void Dispose() { }

    public ChatClientMetadata Metadata { get; } = new("mock");

    public object? GetService(Type serviceType, object? serviceKey = null) => null;

    public Task<ChatResponse> GetResponseAsync(
        IEnumerable<ChatMessage> chatMessages,
        ChatOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        // The last user message contains the response being evaluated
        var userMessage = chatMessages.LastOrDefault(m => m.Role == ChatRole.User)?.Text ?? "";
        var verdict = _respond(userMessage);
        return Task.FromResult(new ChatResponse([new(ChatRole.Assistant, verdict)]));
    }

    public IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(
        IEnumerable<ChatMessage> chatMessages,
        ChatOptions? options = null,
        CancellationToken cancellationToken = default)
        => throw new NotSupportedException("Streaming not needed for guardrail evaluation.");
}
