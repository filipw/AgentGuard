using AgentGuard.Core.Abstractions;

namespace AgentGuard.Azure.ProtectedMaterial;

/// <summary>
/// Options for the Azure Protected Material rule.
/// </summary>
public sealed class AzureProtectedMaterialOptions
{
    /// <summary>
    /// When true, also analyzes code content. Code is taken from
    /// <see cref="GuardrailContext.Properties"/> under the key "Code" (string),
    /// or falls back to analyzing <see cref="GuardrailContext.Text"/> as code.
    /// Default: false (text analysis only).
    /// </summary>
    public bool AnalyzeCode { get; init; }

    /// <summary>
    /// Action to take when protected material is detected.
    /// Defaults to <see cref="ProtectedMaterialAction.Block"/>.
    /// </summary>
    public ProtectedMaterialAction Action { get; init; } = ProtectedMaterialAction.Block;

    /// <summary>
    /// What to do when the Azure API call fails (timeout, 429 exhaustion, HTTP error).
    /// Default: <see cref="ErrorBehavior.FailOpen"/>.
    /// </summary>
    public ErrorBehavior OnError { get; init; } = ErrorBehavior.FailOpen;
}

/// <summary>
/// What to do when protected material is detected.
/// </summary>
public enum ProtectedMaterialAction
{
    /// <summary>Block the response entirely.</summary>
    Block,
    /// <summary>Allow the response but attach detection metadata (citations, license info) for downstream handling.</summary>
    Warn
}

/// <summary>
/// Guardrail rule that uses Azure Content Safety's Protected Material APIs to detect
/// copyrighted text (lyrics, articles, recipes) and code from GitHub repositories
/// in LLM-generated output.
/// Order 76 - runs after LLM copyright rule (75) as a complementary cloud-based check.
/// Fails open on errors.
/// </summary>
public sealed class AzureProtectedMaterialRule : IGuardrailRule
{
    private readonly AzureProtectedMaterialClient _client;
    private readonly AzureProtectedMaterialOptions _options;

    public AzureProtectedMaterialRule(
        AzureProtectedMaterialClient client,
        AzureProtectedMaterialOptions? options = null)
    {
        _client = client;
        _options = options ?? new();
    }

    public string Name => "azure-protected-material";
    public GuardrailPhase Phase => GuardrailPhase.Output;
    public int Order => 76;

    public async ValueTask<GuardrailResult> EvaluateAsync(
        GuardrailContext context, CancellationToken cancellationToken = default)
    {
        // Always check text
        var textResult = await _client.AnalyzeTextAsync(context.Text, cancellationToken);
        if (textResult.IsError)
            return GuardrailResult.Error(Name, _options.OnError);
        if (textResult.Detected)
        {
            return BuildResult(
                "Azure Protected Material detected copyrighted text content (e.g. song lyrics, articles, recipes).",
                ProtectedMaterialType.Text);
        }

        // Optionally check code
        if (_options.AnalyzeCode)
        {
            var code = context.Properties.TryGetValue("Code", out var codeObj) && codeObj is string codeStr
                ? codeStr
                : context.Text;

            var codeResult = await _client.AnalyzeCodeAsync(code, cancellationToken);
            if (codeResult.IsError)
                return GuardrailResult.Error(Name, _options.OnError);
            if (codeResult.Detected)
            {
                var metadata = new Dictionary<string, object>
                {
                    ["materialType"] = "code"
                };

                if (codeResult.CodeCitations.Count > 0)
                {
                    metadata["codeCitations"] = codeResult.CodeCitations.Select(c => new Dictionary<string, object>
                    {
                        ["license"] = c.License,
                        ["sourceUrls"] = c.SourceUrls
                    }).ToList();

                    var licenses = string.Join(", ",
                        codeResult.CodeCitations.Select(c => c.License).Distinct());
                    var reason = $"Azure Protected Material detected code from GitHub repositories (licenses: {licenses}).";

                    return BuildResult(reason, ProtectedMaterialType.Code, metadata);
                }

                return BuildResult(
                    "Azure Protected Material detected code from GitHub repositories.",
                    ProtectedMaterialType.Code, metadata);
            }
        }

        return GuardrailResult.Passed();
    }

    private GuardrailResult BuildResult(
        string reason, ProtectedMaterialType materialType,
        Dictionary<string, object>? metadata = null)
    {
        metadata ??= new Dictionary<string, object>
        {
            ["materialType"] = materialType.ToString().ToLowerInvariant()
        };

        if (!metadata.ContainsKey("materialType"))
            metadata["materialType"] = materialType.ToString().ToLowerInvariant();

        if (_options.Action == ProtectedMaterialAction.Warn)
        {
            return new GuardrailResult
            {
                IsBlocked = false,
                Metadata = metadata
            };
        }

        return new GuardrailResult
        {
            IsBlocked = true,
            Reason = reason,
            Severity = GuardrailSeverity.High,
            Metadata = metadata
        };
    }
}
