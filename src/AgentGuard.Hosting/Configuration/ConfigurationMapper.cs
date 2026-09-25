using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Builders;
using AgentGuard.Core.Configuration;
using AgentGuard.Core.Rules.ContentSafety;
using AgentGuard.Core.Rules.LLM;
using AgentGuard.Core.Rules.Normalization;
using AgentGuard.Core.Rules.PromptInjection;
using AgentGuard.Core.Rules.Retrieval;
using AgentGuard.Core.Rules.Secrets;
using AgentGuard.Core.Rules.TokenLimits;
using AgentGuard.Core.Rules.ToolCall;
using AgentGuard.Core.Rules.ToolResult;
using AgentGuard.Onnx;
using AgentGuard.Pii;
using TasmanianDevil;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.DependencyInjection;

namespace AgentGuard.Hosting.Configuration;

/// <summary>
/// Maps <see cref="PolicyConfiguration"/> to <see cref="GuardrailPolicyBuilder"/> calls.
/// LLM-based and ContentSafety rules resolve their dependencies from <see cref="IServiceProvider"/>.
/// </summary>
internal static class ConfigurationMapper
{
    public static void ApplyConfiguration(
        GuardrailPolicyBuilder builder,
        PolicyConfiguration config,
        IServiceProvider? serviceProvider = null)
    {
        foreach (var rule in config.Rules)
        {
            ApplyRule(builder, rule, serviceProvider);
        }

        if (config.ViolationMessage is not null)
            builder.OnViolation(v => v.RejectWithMessage(config.ViolationMessage));
    }

    private static void ApplyRule(
        GuardrailPolicyBuilder builder,
        RuleConfiguration rule,
        IServiceProvider? serviceProvider)
    {
        switch (rule.Type.ToLowerInvariant())
        {
            case "inputnormalization":
                builder.NormalizeInput(new InputNormalizationOptions
                {
                    DecodeBase64 = rule.DecodeBase64 ?? true,
                    DecodeHex = rule.DecodeHex ?? true,
                    DetectReversedText = rule.DetectReversedText ?? true,
                    NormalizeUnicode = rule.NormalizeUnicode ?? true
                });
                break;

            case "promptinjection":
                var sensitivity = ParseEnum<Sensitivity>(rule.Sensitivity, Sensitivity.Medium);
                builder.BlockPromptInjection(sensitivity);
                break;

            case "piiredaction":
                // Replacement is left null unless configured: hard-coding "[REDACTED]" here made
                // config-driven PII silently differ from the code-driven default (<ENTITY_TYPE> tags).
                builder.RedactPii(new PiiOptions
                {
                    Entities = rule.Entities is { Count: > 0 } ? rule.Entities : null,
                    Replacement = rule.Replacement,
                    Countries = rule.Countries is { Count: > 0 } ? rule.Countries : null,
                });
                break;

            case "tokenlimit":
                var maxTokens = rule.MaxTokens ?? 4000;
                var phase = ParseEnum<GuardrailPhase>(rule.Phase, GuardrailPhase.Input);
                var strategy = ParseEnum<TokenOverflowStrategy>(rule.OverflowStrategy,
                    phase == GuardrailPhase.Input ? TokenOverflowStrategy.Reject : TokenOverflowStrategy.Truncate);

                if (phase == GuardrailPhase.Output)
                    builder.LimitOutputTokens(maxTokens, strategy);
                else
                    builder.LimitInputTokens(maxTokens, strategy);
                break;

            case "contentsafety":
                var classifier = ResolveService<IContentSafetyClassifier>(serviceProvider, "ContentSafety");
                var maxSeverity = ParseEnum<ContentSafetySeverity>(rule.MaxAllowedSeverity, ContentSafetySeverity.Low);
                builder.BlockHarmfulContent(classifier, new ContentSafetyOptions
                {
                    MaxAllowedSeverity = maxSeverity,
                    BlocklistNames = rule.BlocklistNames ?? [],
                    HaltOnBlocklistHit = rule.HaltOnBlocklistHit ?? false
                });
                break;

            case "onnxpromptinjection" when rule.ModelPath is not null:
                // a ModelPath selects the generic DeBERTa rule; without one the bundled Defender model is used
                goto case "debertapromptinjection";

            case "onnxpromptinjection":
            case "defenderpromptinjection":
                builder.BlockPromptInjectionWithDefender(new DefenderPromptInjectionOptions
                {
                    // map the generic config threshold onto the multi-head main-head threshold;
                    // aux veto and temperature use the model-calibrated defaults
                    MainThreshold = rule.Threshold ?? 0.75f
                });
                break;

            case "debertapromptinjection":
                builder.BlockPromptInjectionWithDeberta(new OnnxPromptInjectionOptions
                {
                    ModelPath = rule.ModelPath
                        ?? throw new InvalidOperationException("DebertaPromptInjection requires ModelPath."),
                    TokenizerPath = rule.TokenizerPath
                        ?? throw new InvalidOperationException("DebertaPromptInjection requires TokenizerPath."),
                    Threshold = rule.Threshold ?? 0.5f
                });
                break;

            case "secrets":
                builder.DetectSecrets(new SecretsDetectionOptions
                {
                    Action = ParseEnum<SecretAction>(rule.SecretAction, SecretAction.Block),
                });
                break;

            case "toolcallguardrail":
                builder.GuardToolCalls(new ToolCallGuardrailOptions
                {
                    Categories = ParseEnum<ToolCallInjectionCategory>(rule.Categories, ToolCallInjectionCategory.Default),
                });
                break;

            case "toolresultguardrail":
                builder.GuardToolResults(new ToolResultGuardrailOptions
                {
                    Action = ParseEnum<ToolResultAction>(rule.Action, ToolResultAction.Block),
                    StripUnicodeControl = rule.StripUnicodeControl ?? true,
                });
                break;

            case "retrieval":
                builder.GuardRetrieval(new RetrievalGuardrailOptions
                {
                    DetectPromptInjection = rule.DetectPromptInjection ?? true,
                    DetectSecrets = rule.DetectSecrets ?? true,
                    DetectPII = rule.DetectPii ?? false,
                    Action = ParseEnum<RetrievalFilterAction>(rule.RetrievalAction, RetrievalFilterAction.Remove),
                });
                break;

            case "llmpromptinjection":
                var injectionClient = ResolveService<IChatClient>(serviceProvider, "LlmPromptInjection");
                builder.BlockPromptInjectionWithLlm(injectionClient, new LlmPromptInjectionOptions
                {
                    SystemPrompt = rule.SystemPrompt,
                    IncludeClassification = rule.IncludeClassification ?? true
                });
                break;

            case "llmpiidetection":
                var piiClient = ResolveService<IChatClient>(serviceProvider, "LlmPiiDetection");
                var piiAction = ParseEnum<PiiAction>(rule.PiiAction, PiiAction.Redact);
                builder.DetectPIIWithLlm(piiClient, new LlmPiiDetectionOptions
                {
                    Action = piiAction,
                    SystemPrompt = rule.SystemPrompt
                });
                break;

            case "llmtopicboundary":
                var topicClient = ResolveService<IChatClient>(serviceProvider, "LlmTopicBoundary");
                builder.EnforceTopicBoundaryWithLlm(topicClient, new LlmTopicGuardrailOptions
                {
                    // an empty list is not "allow everything" - it is "allow nothing", which the
                    // judge then applies to every request. Fail at startup instead.
                    AllowedTopics = rule.AllowedTopics is { Count: > 0 }
                        ? rule.AllowedTopics
                        : throw new InvalidOperationException("LlmTopicBoundary requires a non-empty AllowedTopics list."),
                    SystemPrompt = rule.SystemPrompt
                });
                break;

            case "llmoutputpolicy":
                var outputPolicyClient = ResolveService<IChatClient>(serviceProvider, "LlmOutputPolicy");
                builder.EnforceOutputPolicyWithLlm(outputPolicyClient, new LlmOutputPolicyOptions
                {
                    PolicyDescription = rule.PolicyDescription
                        ?? throw new InvalidOperationException("LlmOutputPolicy requires PolicyDescription."),
                    Action = ParseEnum<OutputPolicyAction>(rule.OutputPolicyAction, OutputPolicyAction.Block),
                    SystemPrompt = rule.SystemPrompt
                });
                break;

            case "llmgroundedness":
                var groundednessClient = ResolveService<IChatClient>(serviceProvider, "LlmGroundedness");
                builder.CheckGroundedness(groundednessClient, new LlmGroundednessOptions
                {
                    Action = ParseEnum<GroundednessAction>(rule.GroundednessAction, GroundednessAction.Block),
                    SystemPrompt = rule.SystemPrompt
                });
                break;

            case "llmcopyright":
                var copyrightClient = ResolveService<IChatClient>(serviceProvider, "LlmCopyright");
                builder.CheckCopyright(copyrightClient, new LlmCopyrightOptions
                {
                    Action = ParseEnum<CopyrightAction>(rule.CopyrightAction, CopyrightAction.Block),
                    SystemPrompt = rule.SystemPrompt
                });
                break;

            default:
                // rules that live outside the core engine - the Azure and out-of-process PII
                // adapters, and anything a consumer adds - arrive as registered factories, so this
                // package does not have to reference the assemblies they live in.
                if (TryApplyFactory(builder, rule, serviceProvider))
                    break;

                throw new InvalidOperationException(
                    $"Unknown guardrail rule type: '{rule.Type}'. " +
                    "Valid types: InputNormalization, PromptInjection, OnnxPromptInjection, " +
                    "DefenderPromptInjection, DebertaPromptInjection, PiiRedaction, RemotePii, AzurePii, " +
                    "Secrets, Retrieval, ToolCallGuardrail, ToolResultGuardrail, TokenLimit, ContentSafety, " +
                    "LlmPromptInjection, LlmPiiDetection, LlmTopicBoundary, LlmOutputPolicy, " +
                    "LlmGroundedness, LlmCopyright. " +
                    "RemotePii and AzurePii ship as IGuardrailRuleFactory implementations in " +
                    "AgentGuard.RemotePii and AgentGuard.Azure - register one with " +
                    "services.AddSingleton<IGuardrailRuleFactory, AzurePiiRuleFactory>().");
        }
    }

    private static bool TryApplyFactory(
        GuardrailPolicyBuilder builder, RuleConfiguration rule, IServiceProvider? serviceProvider)
    {
        var factories = serviceProvider?.GetService<IEnumerable<IGuardrailRuleFactory>>();
        if (factories is null)
            return false;

        foreach (var factory in factories)
        {
            if (string.Equals(factory.RuleType, rule.Type, StringComparison.OrdinalIgnoreCase))
            {
                factory.Configure(builder, rule);
                return true;
            }
        }

        return false;
    }

    private static T ResolveService<T>(IServiceProvider? serviceProvider, string ruleType) where T : class
    {
        if (serviceProvider is null)
            throw new InvalidOperationException(
                $"Rule type '{ruleType}' requires {typeof(T).Name} to be registered in DI, " +
                "but no IServiceProvider was available.");

        return serviceProvider.GetService<T>()
            ?? throw new InvalidOperationException(
                $"Rule type '{ruleType}' requires {typeof(T).Name} to be registered in DI. " +
                $"Register it before calling AddAgentGuard, e.g.: services.AddSingleton<{typeof(T).Name}>(...)");
    }

    private static T ParseEnum<T>(string? value, T defaultValue) where T : struct, Enum
    {
        if (string.IsNullOrEmpty(value))
            return defaultValue;

        // Enum.Parse handles the comma-separated flags form too ("SqlInjection, Ssrf")
        return Enum.TryParse<T>(value, ignoreCase: true, out var parsed)
            ? parsed
            : throw new InvalidOperationException(
                $"'{value}' is not a valid {typeof(T).Name}. Valid values: {string.Join(", ", Enum.GetNames<T>())}.");
    }
}
