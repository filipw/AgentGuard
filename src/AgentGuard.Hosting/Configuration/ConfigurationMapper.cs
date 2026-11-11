using System.Globalization;
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
/// Out-of-range settings, and settings the rule type does not read, throw
/// <see cref="InvalidOperationException"/> naming the rule type and setting.
/// </summary>
internal static class ConfigurationMapper
{
    private static readonly string[] DefenderSettings =
    [
        nameof(RuleConfiguration.Threshold),
        nameof(RuleConfiguration.WindowSize),
        nameof(RuleConfiguration.WindowOverlap),
        nameof(RuleConfiguration.MaxWindows),
    ];

    private static readonly string[] DebertaSettings =
    [
        .. DefenderSettings,
        nameof(RuleConfiguration.ModelPath),
        nameof(RuleConfiguration.TokenizerPath),
    ];

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
                RuleSettings.EnsureOnly(
                    rule,
                    nameof(RuleConfiguration.DecodeBase64),
                    nameof(RuleConfiguration.DecodeHex),
                    nameof(RuleConfiguration.DetectReversedText),
                    nameof(RuleConfiguration.NormalizeUnicode));
                builder.NormalizeInput(new InputNormalizationOptions
                {
                    DecodeBase64 = rule.DecodeBase64 ?? true,
                    DecodeHex = rule.DecodeHex ?? true,
                    DetectReversedText = rule.DetectReversedText ?? true,
                    NormalizeUnicode = rule.NormalizeUnicode ?? true
                });
                break;

            case "promptinjection":
                RuleSettings.EnsureOnly(rule, nameof(RuleConfiguration.Sensitivity));
                var sensitivity = ParseEnum<Sensitivity>(rule.Sensitivity, Sensitivity.Medium);
                builder.BlockPromptInjection(sensitivity);
                break;

            case "piiredaction":
                RuleSettings.EnsureOnly(
                    rule,
                    nameof(RuleConfiguration.Entities),
                    nameof(RuleConfiguration.Replacement),
                    nameof(RuleConfiguration.Countries));

                try
                {
                    // an unset Replacement leaves each entity replaced with its <ENTITY_TYPE> tag, the same
                    // default as the code-based RedactPii()
                    builder.RedactPii(new PiiOptions
                    {
                        Entities = rule.Entities is { Count: > 0 } ? rule.Entities : null,
                        Replacement = rule.Replacement,
                        Countries = rule.Countries is { Count: > 0 } ? rule.Countries : null,
                    });
                }
                catch (ArgumentException ex)
                {
                    // an entity name no recognizer detects is a configuration error like the others here
                    var message = ex.ParamName is null
                        ? ex.Message
                        : ex.Message.Replace($" (Parameter '{ex.ParamName}')", "", StringComparison.Ordinal);
                    throw new InvalidOperationException($"{rule.Type}: {message}", ex);
                }

                break;

            case "tokenlimit":
                RuleSettings.EnsureOnly(
                    rule,
                    nameof(RuleConfiguration.MaxTokens),
                    nameof(RuleConfiguration.Phase),
                    nameof(RuleConfiguration.OverflowStrategy));

                var maxTokens = AtLeast(rule, rule.MaxTokens, nameof(RuleConfiguration.MaxTokens), minimum: 1) ?? 4000;
                var phase = ParseEnum<GuardrailPhase>(rule.Phase, GuardrailPhase.Input);

                // Both is two limits, one per direction; each keeps its own default strategy unless one
                // is configured, which then applies to both
                if (phase.HasFlag(GuardrailPhase.Input))
                    builder.LimitInputTokens(maxTokens, ParseEnum(rule.OverflowStrategy, TokenOverflowStrategy.Reject));

                if (phase.HasFlag(GuardrailPhase.Output))
                    builder.LimitOutputTokens(maxTokens, ParseEnum(rule.OverflowStrategy, TokenOverflowStrategy.Truncate));

                break;

            case "contentsafety":
                RuleSettings.EnsureOnly(
                    rule,
                    nameof(RuleConfiguration.MaxAllowedSeverity),
                    nameof(RuleConfiguration.BlocklistNames),
                    nameof(RuleConfiguration.HaltOnBlocklistHit));
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

            case "onnxpromptinjection" when rule.TokenizerPath is not null:
                throw new InvalidOperationException(
                    $"{rule.Type}: TokenizerPath is set without ModelPath. Set both to use your own model, " +
                    "or neither to use the bundled Defender model.");

            case "onnxpromptinjection":
                // ModelPath and TokenizerPath are unset on this path; they are named so that the error
                // for a stray setting lists them
                RuleSettings.EnsureOnly(rule, DebertaSettings);
                builder.BlockPromptInjectionWithDefender(CreateDefenderOptions(rule));
                break;

            case "defenderpromptinjection":
                RuleSettings.EnsureOnly(rule, DefenderSettings);
                builder.BlockPromptInjectionWithDefender(CreateDefenderOptions(rule));
                break;

            case "debertapromptinjection":
                RuleSettings.EnsureOnly(rule, DebertaSettings);
                builder.BlockPromptInjectionWithDeberta(CreateDebertaOptions(rule));
                break;

            case "secrets":
                RuleSettings.EnsureOnly(rule, nameof(RuleConfiguration.SecretAction));
                builder.DetectSecrets(new SecretsDetectionOptions
                {
                    Action = ParseEnum<SecretAction>(rule.SecretAction, SecretAction.Block),
                });
                break;

            case "toolcallguardrail":
                RuleSettings.EnsureOnly(rule, nameof(RuleConfiguration.Categories));
                builder.GuardToolCalls(new ToolCallGuardrailOptions
                {
                    Categories = ParseEnum<ToolCallInjectionCategory>(rule.Categories, ToolCallInjectionCategory.Default),
                });
                break;

            case "toolresultguardrail":
                RuleSettings.EnsureOnly(
                    rule,
                    nameof(RuleConfiguration.Action),
                    nameof(RuleConfiguration.StripUnicodeControl));
                builder.GuardToolResults(new ToolResultGuardrailOptions
                {
                    Action = ParseEnum<ToolResultAction>(rule.Action, ToolResultAction.Block),
                    StripUnicodeControl = rule.StripUnicodeControl ?? true,
                });
                break;

            case "retrieval":
                RuleSettings.EnsureOnly(
                    rule,
                    nameof(RuleConfiguration.DetectPromptInjection),
                    nameof(RuleConfiguration.DetectSecrets),
                    nameof(RuleConfiguration.DetectPii),
                    nameof(RuleConfiguration.RetrievalAction));
                builder.GuardRetrieval(new RetrievalGuardrailOptions
                {
                    DetectPromptInjection = rule.DetectPromptInjection ?? true,
                    DetectSecrets = rule.DetectSecrets ?? true,
                    DetectPII = rule.DetectPii ?? false,
                    Action = ParseEnum<RetrievalFilterAction>(rule.RetrievalAction, RetrievalFilterAction.Remove),
                });
                break;

            case "llmpromptinjection":
                RuleSettings.EnsureOnly(
                    rule,
                    nameof(RuleConfiguration.SystemPrompt),
                    nameof(RuleConfiguration.IncludeClassification));
                var injectionClient = ResolveService<IChatClient>(serviceProvider, "LlmPromptInjection");
                builder.BlockPromptInjectionWithLlm(injectionClient, new LlmPromptInjectionOptions
                {
                    SystemPrompt = rule.SystemPrompt,
                    IncludeClassification = rule.IncludeClassification ?? true
                });
                break;

            case "llmpiidetection":
                RuleSettings.EnsureOnly(
                    rule,
                    nameof(RuleConfiguration.PiiAction),
                    nameof(RuleConfiguration.SystemPrompt));
                var piiClient = ResolveService<IChatClient>(serviceProvider, "LlmPiiDetection");
                var piiAction = ParseEnum<PiiAction>(rule.PiiAction, PiiAction.Redact);
                builder.DetectPIIWithLlm(piiClient, new LlmPiiDetectionOptions
                {
                    Action = piiAction,
                    SystemPrompt = rule.SystemPrompt
                });
                break;

            case "llmtopicboundary":
                RuleSettings.EnsureOnly(
                    rule,
                    nameof(RuleConfiguration.AllowedTopics),
                    nameof(RuleConfiguration.SystemPrompt));
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
                RuleSettings.EnsureOnly(
                    rule,
                    nameof(RuleConfiguration.PolicyDescription),
                    nameof(RuleConfiguration.OutputPolicyAction),
                    nameof(RuleConfiguration.SystemPrompt));
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
                RuleSettings.EnsureOnly(
                    rule,
                    nameof(RuleConfiguration.GroundednessAction),
                    nameof(RuleConfiguration.SystemPrompt));
                var groundednessClient = ResolveService<IChatClient>(serviceProvider, "LlmGroundedness");
                builder.CheckGroundedness(groundednessClient, new LlmGroundednessOptions
                {
                    Action = ParseEnum<GroundednessAction>(rule.GroundednessAction, GroundednessAction.Block),
                    SystemPrompt = rule.SystemPrompt
                });
                break;

            case "llmcopyright":
                RuleSettings.EnsureOnly(
                    rule,
                    nameof(RuleConfiguration.CopyrightAction),
                    nameof(RuleConfiguration.SystemPrompt));
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
                // package does not have to reference the assemblies they live in. A factory knows
                // which settings its rule reads, so rejecting the others is the factory's job.
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

    /// <summary>Options for the bundled Defender model; settings left unset keep the options' defaults.</summary>
    internal static DefenderPromptInjectionOptions CreateDefenderOptions(RuleConfiguration rule)
    {
        var defaults = new DefenderPromptInjectionOptions();
        var (windowSize, windowOverlap, maxWindows) =
            ReadWindowSettings(rule, defaults.WindowSize, defaults.WindowOverlap, defaults.MaxWindows);

        return new DefenderPromptInjectionOptions
        {
            // the generic config threshold maps onto the multi-head main-head threshold;
            // aux veto and temperature use the model-calibrated defaults
            MainThreshold = ReadThreshold(rule, defaults.MainThreshold),
            WindowSize = windowSize,
            WindowOverlap = windowOverlap,
            MaxWindows = maxWindows,
        };
    }

    /// <summary>Options for a bring-your-own DeBERTa model; settings left unset keep the options' defaults.</summary>
    internal static OnnxPromptInjectionOptions CreateDebertaOptions(RuleConfiguration rule)
    {
        var modelPath = rule.ModelPath
            ?? throw new InvalidOperationException($"{rule.Type} requires ModelPath.");
        var tokenizerPath = rule.TokenizerPath
            ?? throw new InvalidOperationException($"{rule.Type} requires TokenizerPath.");

        var defaults = new OnnxPromptInjectionOptions { ModelPath = modelPath, TokenizerPath = tokenizerPath };
        var (windowSize, windowOverlap, maxWindows) =
            ReadWindowSettings(rule, defaults.WindowSize, defaults.WindowOverlap, defaults.MaxWindows);

        return new OnnxPromptInjectionOptions
        {
            ModelPath = modelPath,
            TokenizerPath = tokenizerPath,
            Threshold = ReadThreshold(rule, defaults.Threshold),
            WindowSize = windowSize,
            WindowOverlap = windowOverlap,
            MaxWindows = maxWindows,
        };
    }

    private static float ReadThreshold(RuleConfiguration rule, float defaultValue)
    {
        if (rule.Threshold is not { } threshold)
            return defaultValue;

        // written so that NaN, which fails every comparison, is rejected along with out-of-range values
        if (threshold is not (>= 0f and <= 1f))
        {
            throw new InvalidOperationException(string.Create(CultureInfo.InvariantCulture,
                $"{rule.Type}: Threshold must be a number from 0.0 to 1.0, but was {threshold}."));
        }

        return threshold;
    }

    private static (int WindowSize, int WindowOverlap, int MaxWindows) ReadWindowSettings(
        RuleConfiguration rule, int defaultWindowSize, int defaultWindowOverlap, int defaultMaxWindows)
    {
        var windowSize = AtLeast(rule, rule.WindowSize, nameof(RuleConfiguration.WindowSize), minimum: 1) ?? defaultWindowSize;
        var windowOverlap = AtLeast(rule, rule.WindowOverlap, nameof(RuleConfiguration.WindowOverlap), minimum: 0) ?? defaultWindowOverlap;
        var maxWindows = AtLeast(rule, rule.MaxWindows, nameof(RuleConfiguration.MaxWindows), minimum: 0) ?? defaultMaxWindows;

        if (windowOverlap >= windowSize)
        {
            throw new InvalidOperationException(string.Create(CultureInfo.InvariantCulture,
                $"{rule.Type}: WindowOverlap ({windowOverlap}) must be smaller than WindowSize ({windowSize})."));
        }

        return (windowSize, windowOverlap, maxWindows);
    }

    private static int? AtLeast(RuleConfiguration rule, int? value, string setting, int minimum)
    {
        if (value is { } configured && configured < minimum)
        {
            throw new InvalidOperationException(string.Create(CultureInfo.InvariantCulture,
                $"{rule.Type}: {setting} must be at least {minimum}, but was {configured}."));
        }

        return value;
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

        // only member names are accepted, compared ordinally so the result does not depend on the
        // current culture. Enum.TryParse alone would also take any number, including ones no member
        // defines. A [Flags] enum takes a comma-separated list of names ("SqlInjection, Ssrf").
        var names = Enum.GetNames<T>();
        var parts = typeof(T).IsDefined(typeof(FlagsAttribute), inherit: false)
            ? value.Split(',', StringSplitOptions.TrimEntries)
            : [value.Trim()];

        if (parts.All(part => names.Contains(part, StringComparer.OrdinalIgnoreCase))
            && Enum.TryParse<T>(value, ignoreCase: true, out var parsed))
        {
            return parsed;
        }

        throw new InvalidOperationException(
            $"'{value}' is not a valid {typeof(T).Name}. Valid values: {string.Join(", ", names)}.");
    }
}
