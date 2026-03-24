using Microsoft.Extensions.AI;

namespace AgentGuard.Core.Guardrails;

/// <summary>
/// Options for the re-ask (self-healing) feature. When output guardrails block a response,
/// the pipeline re-prompts the LLM with the failure reason to get a compliant response.
/// </summary>
public sealed class ReaskOptions
{
    /// <summary>
    /// Maximum number of re-ask attempts. Each attempt re-prompts the LLM and re-evaluates
    /// all output guardrails. Default is 1.
    /// </summary>
    public int MaxAttempts { get; set; } = 1;

    /// <summary>
    /// System prompt template for the re-ask. Use <c>{violation_reason}</c> as a placeholder
    /// for the guardrail violation reason, and <c>{original_response}</c> for the blocked response.
    /// </summary>
    public string SystemPromptTemplate { get; set; } =
        "Your previous response was rejected by a safety guardrail for the following reason: {violation_reason}\n\n" +
        "Please provide an alternative response that does not violate this policy. " +
        "Do not acknowledge the rejection or mention guardrails - just provide the corrected response.";

    /// <summary>
    /// Optional <see cref="ChatOptions"/> passed to the LLM during re-ask calls.
    /// </summary>
    public ChatOptions? ChatOptions { get; set; }

    /// <summary>
    /// Whether to include the blocked response in the re-ask conversation history.
    /// Default is true, which helps the LLM understand what to avoid.
    /// </summary>
    public bool IncludeBlockedResponse { get; set; } = true;
}
