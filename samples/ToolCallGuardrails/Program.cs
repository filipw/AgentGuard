// AgentGuard — Tool Call Guardrails Sample
// Demonstrates how AgentGuard automatically inspects tool call arguments for injection attacks
// when integrated into the Microsoft Agent Framework (MAF) middleware pipeline.
//
// The guardrail sits between the LLM and tool execution — if the LLM generates a malicious
// tool call (e.g. SQL injection, path traversal, SSRF), AgentGuard blocks the response
// before the tool is ever invoked.
//
// Requirements:
//   Set environment variables before running:
//     AGENTGUARD_LLM_ENDPOINT  — base URL of an OpenAI-compatible API (e.g. http://localhost:1234/v1/)
//     AGENTGUARD_LLM_MODEL     — model name (e.g. qwen2.5-7b, llama3.1-8b, etc.)
//     AGENTGUARD_LLM_KEY       — API key (optional, defaults to "unused" for local servers)
//
// NOTE: This sample is designed for local LLMs (Ollama, LM Studio, vLLM, etc.)
// because cloud endpoints may reject prompts that attempt to elicit malicious tool calls.

using System.ClientModel;
using System.ComponentModel;
using AgentGuard.AgentFramework;
using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Rules.ToolCall;
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;
using OpenAI;

var endpoint = Environment.GetEnvironmentVariable("AGENTGUARD_LLM_ENDPOINT");
var model = Environment.GetEnvironmentVariable("AGENTGUARD_LLM_MODEL");
var key = Environment.GetEnvironmentVariable("AGENTGUARD_LLM_KEY") ?? "unused";

if (string.IsNullOrEmpty(endpoint) || string.IsNullOrEmpty(model))
{
    Console.Error.WriteLine("Set AGENTGUARD_LLM_ENDPOINT and AGENTGUARD_LLM_MODEL to run this sample.");
    Console.Error.WriteLine("  Example (Ollama): AGENTGUARD_LLM_ENDPOINT=http://localhost:11434/v1/ AGENTGUARD_LLM_MODEL=qwen2.5:7b");
    Console.Error.WriteLine("  Example (LM Studio): AGENTGUARD_LLM_ENDPOINT=http://localhost:1234/v1/ AGENTGUARD_LLM_MODEL=local-model");
    return 1;
}

// ─── Define Tools ──────────────────────────────────────────────────────────
// These are the tools available to the agent. In a real app, they would query
// databases, call APIs, read files, etc. The guardrail protects them from
// receiving malicious arguments.

[Description("Query the customer database by SQL. Returns matching customer records.")]
static string QueryCustomers([Description("SQL query to execute against the customers table")] string sql)
{
    Console.WriteLine($"    [Tool executed] QueryCustomers(sql: {sql})");
    return """[{"id": 1, "name": "Alice Smith", "plan": "Premium"}]""";
}

[Description("Read a file from the document store.")]
static string ReadDocument([Description("File path relative to the documents root")] string path)
{
    Console.WriteLine($"    [Tool executed] ReadDocument(path: {path})");
    return "Document content: This is the company policy on returns.";
}

[Description("Fetch data from an external URL.")]
static string FetchUrl([Description("The URL to fetch data from")] string url)
{
    Console.WriteLine($"    [Tool executed] FetchUrl(url: {url})");
    return "Fetched content: OK";
}

// ─── Create Agent with Tool Call Guardrails ────────────────────────────────

var openAiClient = new OpenAIClient(new ApiKeyCredential(key),
    new OpenAIClientOptions { Endpoint = new Uri(endpoint) });
var chatClient = openAiClient.GetChatClient(model).AsIChatClient();

Console.WriteLine("AgentGuard — Tool Call Guardrails Demo");
Console.WriteLine($"  Endpoint: {endpoint}");
Console.WriteLine($"  Model:    {model}");
Console.WriteLine(new string('=', 60));

var agent = chatClient
    .AsAIAgent(
        instructions: """
            You are a helpful customer support agent with access to tools.
            Use the QueryCustomers tool to look up customer information.
            Use the ReadDocument tool to read company documents.
            Use the FetchUrl tool to retrieve external data.
            Always use the tools when the user asks for data.
            """,
        name: "SupportBot",
        tools:
        [
            AIFunctionFactory.Create(QueryCustomers),
            AIFunctionFactory.Create(ReadDocument),
            AIFunctionFactory.Create(FetchUrl)
        ])
    .AsBuilder()
    .UseAgentGuard(g => g
        .NormalizeInput()
        .BlockPromptInjection()
        .GuardToolCalls()  // <-- This is the key addition
        .OnViolation(v => v.RejectWithMessage("I can't process that request — a safety guardrail was triggered."))
    )
    .Build();

// ─── Example 1: Normal Tool Usage ─────────────────────────────────────────

Console.WriteLine("\n[1] Normal Tool Usage (should pass)");
Console.WriteLine(new string('-', 60));
Console.WriteLine("  User: Show me our premium customers");
var response = await agent.RunAsync("Show me our premium customers");
Console.WriteLine($"  Response: {Truncate(response.ToString())}");

// ─── Example 2: Direct Tool Call Evaluation ────────────────────────────────
// Demonstrates using the ToolCallGuardrailRule directly (standalone, no agent framework).
// This is useful for validating tool calls before execution in custom agent loops.

Console.WriteLine("\n\n[2] Direct Tool Call Evaluation (standalone, no agent)");
Console.WriteLine(new string('-', 60));

var toolCallRule = new ToolCallGuardrailRule();

// Safe tool call
var safeCall = new AgentToolCall
{
    ToolName = "QueryCustomers",
    Arguments = new Dictionary<string, string> { ["sql"] = "SELECT name, plan FROM customers WHERE plan = 'Premium'" }
};
var safeResult = await toolCallRule.EvaluateAsync(
    new() { Text = "", Phase = GuardrailPhase.Output, Properties = { [ToolCallGuardrailRule.ToolCallsKey] = (IReadOnlyList<AgentToolCall>)[safeCall] } });
Console.WriteLine($"  Safe SQL query:   {(safeResult.IsBlocked ? "BLOCKED" : "PASSED")}");

// SQL injection
var sqlInjection = new AgentToolCall
{
    ToolName = "QueryCustomers",
    Arguments = new Dictionary<string, string> { ["sql"] = "SELECT * FROM customers WHERE id=1 UNION SELECT password FROM admin_users" }
};
var sqlResult = await toolCallRule.EvaluateAsync(
    new() { Text = "", Phase = GuardrailPhase.Output, Properties = { [ToolCallGuardrailRule.ToolCallsKey] = (IReadOnlyList<AgentToolCall>)[sqlInjection] } });
Console.WriteLine($"  SQL injection:    {(sqlResult.IsBlocked ? "BLOCKED" : "PASSED")} — {sqlResult.Reason}");

// Path traversal
var pathTraversal = new AgentToolCall
{
    ToolName = "ReadDocument",
    Arguments = new Dictionary<string, string> { ["path"] = "../../../etc/passwd" }
};
var pathResult = await toolCallRule.EvaluateAsync(
    new() { Text = "", Phase = GuardrailPhase.Output, Properties = { [ToolCallGuardrailRule.ToolCallsKey] = (IReadOnlyList<AgentToolCall>)[pathTraversal] } });
Console.WriteLine($"  Path traversal:   {(pathResult.IsBlocked ? "BLOCKED" : "PASSED")} — {pathResult.Reason}");

// SSRF to cloud metadata
var ssrf = new AgentToolCall
{
    ToolName = "FetchUrl",
    Arguments = new Dictionary<string, string> { ["url"] = "http://169.254.169.254/latest/meta-data/iam/security-credentials/" }
};
var ssrfResult = await toolCallRule.EvaluateAsync(
    new() { Text = "", Phase = GuardrailPhase.Output, Properties = { [ToolCallGuardrailRule.ToolCallsKey] = (IReadOnlyList<AgentToolCall>)[ssrf] } });
Console.WriteLine($"  SSRF metadata:    {(ssrfResult.IsBlocked ? "BLOCKED" : "PASSED")} — {ssrfResult.Reason}");

// Command injection
var cmdInjection = new AgentToolCall
{
    ToolName = "ReadDocument",
    Arguments = new Dictionary<string, string> { ["path"] = "report.pdf; cat /etc/shadow" }
};
var cmdResult = await toolCallRule.EvaluateAsync(
    new() { Text = "", Phase = GuardrailPhase.Output, Properties = { [ToolCallGuardrailRule.ToolCallsKey] = (IReadOnlyList<AgentToolCall>)[cmdInjection] } });
Console.WriteLine($"  Command injection: {(cmdResult.IsBlocked ? "BLOCKED" : "PASSED")} — {cmdResult.Reason}");

// ─── Example 3: Tool Allowlists ────────────────────────────────────────────
// You can allowlist specific tools or arguments that legitimately accept code/SQL.

Console.WriteLine("\n\n[3] Tool Allowlists");
Console.WriteLine(new string('-', 60));

var allowlistedRule = new ToolCallGuardrailRule(new ToolCallGuardrailOptions
{
    // The "code_executor" tool legitimately receives code — skip it
    AllowedTools = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "code_executor" },
    // The "sql" argument on the "analytics" tool is intentional SQL — skip it
    PerToolAllowedArguments = new Dictionary<string, ISet<string>>(StringComparer.OrdinalIgnoreCase)
    {
        ["analytics"] = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "query" }
    }
});

var codeCall = new AgentToolCall
{
    ToolName = "code_executor",
    Arguments = new Dictionary<string, string> { ["code"] = "eval('__import__(\"os\").system(\"ls\")')" }
};
var codeResult = await allowlistedRule.EvaluateAsync(
    new() { Text = "", Phase = GuardrailPhase.Output, Properties = { [ToolCallGuardrailRule.ToolCallsKey] = (IReadOnlyList<AgentToolCall>)[codeCall] } });
Console.WriteLine($"  Allowlisted tool (code_executor): {(codeResult.IsBlocked ? "BLOCKED" : "PASSED (allowlisted)")}");

var analyticsCall = new AgentToolCall
{
    ToolName = "analytics",
    Arguments = new Dictionary<string, string> { ["query"] = "SELECT COUNT(*) FROM users UNION SELECT 1" }
};
var analyticsResult = await allowlistedRule.EvaluateAsync(
    new() { Text = "", Phase = GuardrailPhase.Output, Properties = { [ToolCallGuardrailRule.ToolCallsKey] = (IReadOnlyList<AgentToolCall>)[analyticsCall] } });
Console.WriteLine($"  Allowlisted arg (analytics.query): {(analyticsResult.IsBlocked ? "BLOCKED" : "PASSED (allowlisted)")}");

Console.WriteLine($"\n{new string('=', 60)}");
Console.WriteLine("Done.");
return 0;

// ─── Helpers ───────────────────────────────────────────────────────────────

static string Truncate(string text, int maxLen = 120) =>
    text.Length > maxLen ? text[..(maxLen - 3)] + "..." : text;
