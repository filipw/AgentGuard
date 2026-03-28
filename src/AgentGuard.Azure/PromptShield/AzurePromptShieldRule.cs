using AgentGuard.Core.Abstractions;

namespace AgentGuard.Azure.PromptShield;

/// <summary>
/// Options for the Azure Prompt Shield rule.
/// </summary>
public sealed class AzurePromptShieldOptions
{
    /// <summary>
    /// When true, also analyzes documents passed via <see cref="GuardrailContext.Properties"/>
    /// under the key "Documents" (List&lt;string&gt;). Detects indirect injection in grounded content.
    /// Default: false.
    /// </summary>
    public bool AnalyzeDocuments { get; init; }

    /// <summary>
    /// What to do when the Azure API call fails (timeout, 429 exhaustion, HTTP error).
    /// Default: <see cref="ErrorBehavior.FailOpen"/>.
    /// </summary>
    public ErrorBehavior OnError { get; init; } = ErrorBehavior.FailOpen;
}

/// <summary>
/// Guardrail rule that uses Azure Content Safety's Prompt Shield API to detect
/// user prompt attacks (jailbreaks) and document attacks (indirect injection).
/// Order 14 - runs between remote ML classifiers (13) and LLM-as-judge (15).
/// Fails open on errors.
/// </summary>
public sealed class AzurePromptShieldRule : IGuardrailRule
{
    private readonly AzurePromptShieldClient _client;
    private readonly AzurePromptShieldOptions _options;

    public AzurePromptShieldRule(AzurePromptShieldClient client, AzurePromptShieldOptions? options = null)
    {
        _client = client;
        _options = options ?? new();
    }

    public string Name => "azure-prompt-shield";
    public GuardrailPhase Phase => GuardrailPhase.Input;
    public int Order => 14;

    public async ValueTask<GuardrailResult> EvaluateAsync(
        GuardrailContext context, CancellationToken cancellationToken = default)
    {
        IReadOnlyList<string>? documents = null;
        if (_options.AnalyzeDocuments &&
            context.Properties.TryGetValue("Documents", out var docs) &&
            docs is IReadOnlyList<string> docList)
        {
            documents = docList;
        }

        var result = documents is { Count: > 0 }
            ? await _client.AnalyzeAsync(context.Text, documents, cancellationToken)
            : await _client.AnalyzeUserPromptAsync(context.Text, cancellationToken);

        if (result.IsError)
            return GuardrailResult.Error(Name, _options.OnError);

        if (result.UserPromptAttackDetected)
        {
            return new GuardrailResult
            {
                IsBlocked = true,
                Reason = "Azure Prompt Shield detected a user prompt attack (jailbreak/injection attempt).",
                Severity = GuardrailSeverity.High,
                Metadata = new Dictionary<string, object>
                {
                    ["attackType"] = "userPrompt"
                }
            };
        }

        for (var i = 0; i < result.DocumentAttacksDetected.Count; i++)
        {
            if (result.DocumentAttacksDetected[i])
            {
                return new GuardrailResult
                {
                    IsBlocked = true,
                    Reason = $"Azure Prompt Shield detected an indirect injection attack in document {i}.",
                    Severity = GuardrailSeverity.High,
                    Metadata = new Dictionary<string, object>
                    {
                        ["attackType"] = "document",
                        ["documentIndex"] = i
                    }
                };
            }
        }

        return GuardrailResult.Passed();
    }
}
