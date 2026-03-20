using AgentGuard.Core.Abstractions;
using Microsoft.Extensions.AI;

namespace AgentGuard.Core.Rules.LLM;

/// <summary>
/// What to do when a policy violation is detected.
/// </summary>
public enum OutputPolicyAction
{
    /// <summary>Block the response entirely.</summary>
    Block,
    /// <summary>Allow the response but attach violation metadata for downstream handling.</summary>
    Warn
}

/// <summary>
/// Options for LLM-based output policy enforcement.
/// </summary>
public sealed class LlmOutputPolicyOptions
{
    /// <summary>
    /// A natural language description of the policy to enforce.
    /// Example: "Never recommend competitor products" or "Always include a disclaimer about medical advice".
    /// </summary>
    public required string PolicyDescription { get; init; }

    /// <summary>
    /// Action to take when a violation is detected. Defaults to <see cref="OutputPolicyAction.Block"/>.
    /// </summary>
    public OutputPolicyAction Action { get; init; } = OutputPolicyAction.Block;

    /// <summary>
    /// Optional custom system prompt override. If null, the built-in prompt template is used.
    /// Use {policy} as a placeholder for the policy description.
    /// </summary>
    public string? SystemPrompt { get; init; }
}

/// <summary>
/// Checks whether an agent's response violates custom policy constraints using an LLM classifier.
/// Useful for brand safety, compliance, and operational guardrails on output.
/// </summary>
public sealed class LlmOutputPolicyRule : LlmGuardrailRule
{
    private readonly LlmOutputPolicyOptions _options;
    private readonly string _systemPrompt;

    public LlmOutputPolicyRule(IChatClient chatClient, LlmOutputPolicyOptions options, ChatOptions? chatOptions = null)
        : base(chatClient, chatOptions)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _systemPrompt = _options.SystemPrompt?.Replace("{policy}", _options.PolicyDescription)
            ?? GetDefaultPrompt(_options.PolicyDescription);
    }

    public override string Name => "llm-output-policy";
    public override GuardrailPhase Phase => GuardrailPhase.Output;
    public override int Order => 55;

    internal static string GetDefaultPrompt(string policyDescription) =>
        $"""
        You are a compliance checker. Your task is to determine whether an AI assistant's response
        violates a specific policy constraint.

        Policy: {policyDescription}

        Analyze the response and determine if it violates the above policy.

        Respond in exactly one of these formats:
        - COMPLIANT if the response does not violate the policy
        - VIOLATION|reason:<brief reason> if the response violates the policy

        Do not explain your reasoning beyond the reason field. Respond with only the verdict line.
        """;

    protected override IEnumerable<ChatMessage> BuildPrompt(GuardrailContext context) =>
    [
        new(ChatRole.System, _systemPrompt),
        new(ChatRole.User, context.Text)
    ];

    protected override GuardrailResult ParseResponse(string responseText, GuardrailContext context)
    {
        var trimmed = responseText.Trim();
        var upper = trimmed.ToUpperInvariant();

        if (!upper.Contains("VIOLATION", StringComparison.Ordinal))
            return GuardrailResult.Passed();

        var reason = ParseReason(trimmed);

        if (_options.Action == OutputPolicyAction.Warn)
        {
            return new GuardrailResult
            {
                IsBlocked = false,
                Metadata = new Dictionary<string, object>
                {
                    ["violation_reason"] = reason,
                    ["policy"] = _options.PolicyDescription
                }
            };
        }

        return new GuardrailResult
        {
            IsBlocked = true,
            Reason = $"Response violates output policy: {reason}",
            Severity = GuardrailSeverity.Medium,
            Metadata = new Dictionary<string, object>
            {
                ["violation_reason"] = reason,
                ["policy"] = _options.PolicyDescription
            }
        };
    }

    internal static string ParseReason(string response)
    {
        var parts = response.Split('|', StringSplitOptions.RemoveEmptyEntries);
        foreach (var part in parts.Skip(1))
        {
            var kv = part.Split(':', 2, StringSplitOptions.TrimEntries);
            if (kv.Length == 2 && kv[0].Equals("reason", StringComparison.OrdinalIgnoreCase))
                return kv[1];
        }

        return "Policy violation detected.";
    }
}
