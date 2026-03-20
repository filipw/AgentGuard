using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Builders;
using AgentGuard.Core.Rules.ContentSafety;
using AgentGuard.Core.Rules.LLM;
using AgentGuard.Core.Rules.Normalization;
using AgentGuard.Core.Rules.PII;
using AgentGuard.Core.Rules.PromptInjection;
using AgentGuard.Core.Rules.TokenLimits;
using AgentGuard.Core.Rules.TopicBoundary;
using AgentGuard.Onnx;
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
                var categories = ParseEnum<PiiCategory>(rule.Categories, PiiCategory.Default);
                builder.RedactPII(categories, rule.Replacement ?? "[REDACTED]");
                break;

            case "topicboundary":
                var topics = rule.AllowedTopics?.ToArray() ?? [];
                if (rule.SimilarityThreshold.HasValue)
                    builder.EnforceTopicBoundary(rule.SimilarityThreshold.Value, topics);
                else
                    builder.EnforceTopicBoundary(topics);
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

            case "onnxpromptinjection":
                builder.BlockPromptInjectionWithOnnx(new OnnxPromptInjectionOptions
                {
                    ModelPath = rule.ModelPath
                        ?? throw new InvalidOperationException("OnnxPromptInjection requires ModelPath."),
                    TokenizerPath = rule.TokenizerPath
                        ?? throw new InvalidOperationException("OnnxPromptInjection requires TokenizerPath."),
                    Threshold = rule.Threshold ?? 0.5f
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
                    AllowedTopics = rule.AllowedTopics ?? [],
                    SystemPrompt = rule.SystemPrompt
                });
                break;

            case "outputtopicboundary":
                var outputTopics = rule.AllowedTopics?.ToArray() ?? [];
                var outputTopicOpts = new OutputTopicBoundaryOptions
                {
                    AllowedTopics = outputTopics.ToList(),
                    SimilarityThreshold = rule.SimilarityThreshold ?? 0.3f,
                    Action = ParseEnum<OutputTopicAction>(rule.OutputTopicAction, OutputTopicAction.Block)
                };
                builder.EnforceOutputTopicBoundary(outputTopicOpts);
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
                throw new InvalidOperationException(
                    $"Unknown guardrail rule type: '{rule.Type}'. " +
                    "Valid types: InputNormalization, PromptInjection, OnnxPromptInjection, PiiRedaction, " +
                    "TopicBoundary, OutputTopicBoundary, TokenLimit, ContentSafety, LlmPromptInjection, " +
                    "LlmPiiDetection, LlmTopicBoundary, LlmOutputPolicy, LlmGroundedness, LlmCopyright.");
        }
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

    private static T ParseEnum<T>(string? value, T defaultValue) where T : struct, Enum =>
        string.IsNullOrEmpty(value) ? defaultValue : Enum.Parse<T>(value, ignoreCase: true);
}
