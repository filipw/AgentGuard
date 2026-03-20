// AgentGuard — Output Guardrails Sample
// Demonstrates LLM-based output validation: policy enforcement, groundedness checking, and copyright detection.
// These rules run on agent responses (output phase) to catch violations before they reach the user.
//
// Requirements:
//   Set environment variables before running:
//     AGENTGUARD_LLM_ENDPOINT  — base URL of an OpenAI-compatible API (e.g. http://localhost:1234/v1/)
//     AGENTGUARD_LLM_MODEL     — model name (e.g. openai/gpt-oss-20b, gpt-4o-mini)
//     AGENTGUARD_LLM_KEY       — API key (optional, defaults to "unused" for local servers)

using System.ClientModel;
using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Builders;
using AgentGuard.Core.Guardrails;
using AgentGuard.Core.Rules.LLM;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.Logging.Abstractions;
using OpenAI;

var endpoint = Environment.GetEnvironmentVariable("AGENTGUARD_LLM_ENDPOINT");
var model = Environment.GetEnvironmentVariable("AGENTGUARD_LLM_MODEL");
var key = Environment.GetEnvironmentVariable("AGENTGUARD_LLM_KEY") ?? "unused";

if (string.IsNullOrEmpty(endpoint) || string.IsNullOrEmpty(model))
{
    Console.Error.WriteLine("Set AGENTGUARD_LLM_ENDPOINT and AGENTGUARD_LLM_MODEL to run this sample.");
    Console.Error.WriteLine("  Example: AGENTGUARD_LLM_ENDPOINT=http://localhost:1234/v1/ AGENTGUARD_LLM_MODEL=gpt-4o-mini");
    return 1;
}

var openAiClient = new OpenAIClient(new ApiKeyCredential(key),
    new OpenAIClientOptions { Endpoint = new Uri(endpoint) });
using var chatClient = openAiClient.GetChatClient(model).AsIChatClient();
var chatOptions = new ChatOptions { MaxOutputTokens = 500, Temperature = 0f };

Console.WriteLine("AgentGuard — Output Guardrails Demo");
Console.WriteLine($"  Endpoint: {endpoint}");
Console.WriteLine($"  Model:    {model}");
Console.WriteLine(new string('=', 60));

// ─── Example 1: Output Policy Enforcement ───────────────────────────────
// Block responses that recommend competitor products.

Console.WriteLine("\n[1] Output Policy Enforcement");
Console.WriteLine(new string('─', 60));

var policyPipeline = new GuardrailPipeline(
    new GuardrailPolicyBuilder("output-policy-demo")
        .EnforceOutputPolicy(chatClient,
            "The assistant must never recommend, suggest, or mention competitor products by name. " +
            "Our product is AgentCRM. Any mention of another CRM product is a violation.",
            chatOptions: chatOptions)
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
    Console.WriteLine($"\n  [{label}] \"{Truncate(response)}\"");
    var ctx = new GuardrailContext { Text = response, Phase = GuardrailPhase.Output };
    var result = await policyPipeline.RunAsync(ctx);
    PrintResult(result);
}

// ─── Example 2: Groundedness Checking ───────────────────────────────────
// Detect hallucinated facts not supported by conversation context.

Console.WriteLine($"\n\n[2] Groundedness Checking");
Console.WriteLine(new string('─', 60));

var groundednessPipeline = new GuardrailPipeline(
    new GuardrailPolicyBuilder("groundedness-demo")
        .CheckGroundedness(chatClient, chatOptions: chatOptions)
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
    Console.WriteLine($"\n  [{label}] \"{Truncate(response)}\"");
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
// Detect reproduction of copyrighted material.
// Uses public domain content (Dickens) to avoid triggering content filters on the LLM endpoint.

Console.WriteLine($"\n\n[3] Copyright Detection");
Console.WriteLine(new string('─', 60));

var copyrightPipeline = new GuardrailPipeline(
    new GuardrailPolicyBuilder("copyright-demo")
        .CheckCopyright(chatClient, chatOptions: chatOptions)
        .Build(),
    NullLogger<GuardrailPipeline>.Instance);

var copyrightScenarios = new (string Label, string Response)[]
{
    ("Original", "Dickens wrote about social inequality in Victorian England, focusing on themes of poverty and redemption."),
    ("Extended reproduction", """
        It was the best of times, it was the worst of times, it was the age of wisdom,
        it was the age of foolishness, it was the epoch of belief, it was the epoch of
        incredulity, it was the season of Light, it was the season of Darkness, it was
        the spring of hope, it was the winter of despair, we had everything before us,
        we had nothing before us, we were all going direct to Heaven, we were all going
        direct the other way.
        """),
    ("Short quote", "As Dickens wrote, \"it was the best of times\" — a famous opening line."),
};

foreach (var (label, response) in copyrightScenarios)
{
    var display = response.Replace("\n", " ").Trim();
    Console.WriteLine($"\n  [{label}] \"{Truncate(display)}\"");
    var ctx = new GuardrailContext { Text = response, Phase = GuardrailPhase.Output };
    var result = await copyrightPipeline.RunAsync(ctx);
    PrintResult(result);
}

// ─── Example 4: Combined Output Pipeline ────────────────────────────────
// All three output rules in a single pipeline — rules execute in order (55 → 65 → 75).

Console.WriteLine($"\n\n[4] Combined Output Pipeline (Policy + Groundedness + Copyright)");
Console.WriteLine(new string('─', 60));

var combinedPipeline = new GuardrailPipeline(
    new GuardrailPolicyBuilder("combined-output")
        .EnforceOutputPolicy(chatClient,
            "The assistant must never recommend, suggest, or mention competitor products by name. " +
            "Our product is AgentCRM. Any mention of another CRM product is a violation.",
            chatOptions: chatOptions)
        .CheckGroundedness(chatClient, chatOptions: chatOptions)
        .CheckCopyright(chatClient, chatOptions: chatOptions)
        .Build(),
    NullLogger<GuardrailPipeline>.Instance);

var combinedScenarios = new (string Label, string Response)[]
{
    ("Clean", "Your order #12345 shipped on March 15th via FedEx. Your tracking number is FX-9876543."),
    ("Policy violation", "Have you considered switching to CompetitorCRM? Their free tier is quite generous."),
    ("Hallucinated", "Our company, founded in 1987, processes orders 47% faster than any other provider."),
};

foreach (var (label, response) in combinedScenarios)
{
    Console.WriteLine($"\n  [{label}] \"{Truncate(response)}\"");
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
        .EnforceOutputPolicy(chatClient,
            "The assistant must never recommend or mention competitor products by name. Our product is AgentCRM.",
            OutputPolicyAction.Warn, chatOptions)
        .CheckGroundedness(chatClient, new LlmGroundednessOptions { Action = GroundednessAction.Warn }, chatOptions)
        .Build(),
    NullLogger<GuardrailPipeline>.Instance);

var warnResponse = "Have you considered CompetitorCRM? Their support is excellent.";
Console.WriteLine($"\n  Input: \"{warnResponse}\"");
var warnCtx = new GuardrailContext { Text = warnResponse, Phase = GuardrailPhase.Output, Messages = conversationHistory };
var warnResult = await warnPipeline.RunAsync(warnCtx);

Console.WriteLine($"  Blocked: {warnResult.IsBlocked}");
Console.WriteLine("  Response passes through (warn mode), but metadata is attached:");
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
Console.WriteLine("Done.");
return 0;

// ─── Helpers ─────────────────────────────────────────────────────────────

static string Truncate(string text, int maxLen = 80) =>
    text.Length > maxLen ? text[..(maxLen - 3)] + "..." : text;

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
