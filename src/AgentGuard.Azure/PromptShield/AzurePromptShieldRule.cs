using AgentGuard.Core.Abstractions;

namespace AgentGuard.Azure.PromptShield;

/// <summary>
/// Options for the Azure Prompt Shield rule.
/// </summary>
public sealed class AzurePromptShieldOptions
{
    /// <summary>
    /// When true, also analyzes documents passed via <see cref="GuardrailContext.Properties"/>
    /// under <see cref="AzurePromptShieldRule.DocumentsKey"/>: any sequence of strings, or a single
    /// string. Detects indirect injection in grounded content. Default: false.
    /// </summary>
    public bool AnalyzeDocuments { get; init; }

    /// <summary>
    /// What to do when the Azure API call fails (timeout, 429 exhaustion, HTTP error, or a success
    /// response without the analysis). Default: <see cref="ErrorBehavior.FailOpen"/>.
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
    /// <summary>
    /// The <see cref="GuardrailContext.Properties"/> key under which the host passes the documents
    /// that accompany the prompt (retrieved chunks, tool output, attachments), analyzed when
    /// <see cref="AzurePromptShieldOptions.AnalyzeDocuments"/> is on. The value is any
    /// <see cref="IEnumerable{T}"/> of <see cref="string"/>, or a single <see cref="string"/>.
    /// </summary>
    public const string DocumentsKey = "Documents";

    private readonly AzurePromptShieldClient _client;
    private readonly AzurePromptShieldOptions _options;

    /// <summary>Initializes a new instance of the <see cref="AzurePromptShieldRule"/> class.</summary>
    /// <param name="client">The configured Azure client.</param>
    /// <param name="options">Rule options. Defaults when null.</param>
    public AzurePromptShieldRule(AzurePromptShieldClient client, AzurePromptShieldOptions? options = null)
    {
        _client = client;
        _options = options ?? new();
    }

    /// <inheritdoc />
    public string Name => "azure-prompt-shield";
    /// <inheritdoc />
    public GuardrailPhase Phase => GuardrailPhase.Input;
    /// <inheritdoc />
    public int Order => 14;

    /// <inheritdoc />
    public async ValueTask<GuardrailResult> EvaluateAsync(
        GuardrailContext context, CancellationToken cancellationToken = default)
    {
        // every other rule short-circuits here; without it an empty turn costs a billable call and
        // usually comes back 400.
        if (string.IsNullOrWhiteSpace(context.Text))
            return GuardrailResult.Passed();

        var documents = _options.AnalyzeDocuments && context.Properties.TryGetValue(DocumentsKey, out var value)
            ? ReadDocuments(value)
            : null;

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

    // hosts hand the documents over in whatever collection they have, so any sequence of strings
    // counts, and a lone string is one document. A null entry keeps its place as an empty document,
    // so the reported document index still matches the host's collection.
    private static List<string>? ReadDocuments(object? value) => value switch
    {
        string single => [single],
        IEnumerable<string?> many => many.Select(document => document ?? "").ToList(),
        _ => null
    };
}
