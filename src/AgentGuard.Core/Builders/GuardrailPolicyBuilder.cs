using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Rules.ContentSafety;
using AgentGuard.Core.Rules.LLM;
using AgentGuard.Core.Rules.Normalization;
using AgentGuard.Core.Rules.PII;
using AgentGuard.Core.Rules.PromptInjection;
using AgentGuard.Core.Rules.TokenLimits;
using AgentGuard.Core.Rules.TopicBoundary;
using AgentGuard.Core.Streaming;
using Microsoft.Extensions.AI;

namespace AgentGuard.Core.Builders;

public sealed class GuardrailPolicyBuilder
{
    private readonly string _name;
    private readonly List<IGuardrailRule> _rules = [];
    private IViolationHandler? _violationHandler;
    private ProgressiveStreamingOptions? _progressiveStreaming;

    public GuardrailPolicyBuilder(string name = "default") => _name = name;

    /// <summary>
    /// Adds input normalization that decodes common evasion encodings (base64, hex, reversed text,
    /// Unicode homoglyphs) so downstream rules see plaintext. Runs before all other rules (order 5).
    /// </summary>
    public GuardrailPolicyBuilder NormalizeInput(InputNormalizationOptions? options = null)
    {
        _rules.Add(new InputNormalizationRule(options));
        return this;
    }

    public GuardrailPolicyBuilder BlockPromptInjection(Sensitivity sensitivity = Sensitivity.Medium)
    {
        _rules.Add(new PromptInjectionRule(new PromptInjectionOptions { Sensitivity = sensitivity }));
        return this;
    }

    public GuardrailPolicyBuilder RedactPII(PiiCategory categories = PiiCategory.Default, string replacement = "[REDACTED]")
    {
        _rules.Add(new PiiRedactionRule(new PiiRedactionOptions { Categories = categories, Replacement = replacement }));
        return this;
    }

    public GuardrailPolicyBuilder EnforceTopicBoundary(params string[] allowedTopics)
    {
        _rules.Add(new TopicBoundaryRule(new TopicBoundaryOptions { AllowedTopics = allowedTopics.ToList() }));
        return this;
    }

    public GuardrailPolicyBuilder EnforceTopicBoundary(float similarityThreshold, params string[] allowedTopics)
    {
        _rules.Add(new TopicBoundaryRule(new TopicBoundaryOptions
        {
            AllowedTopics = allowedTopics.ToList(),
            SimilarityThreshold = similarityThreshold
        }));
        return this;
    }

    /// <summary>
    /// Adds topic boundary enforcement with a custom similarity provider (e.g. embedding-based).
    /// </summary>
    public GuardrailPolicyBuilder EnforceTopicBoundary(ITopicSimilarityProvider provider, params string[] allowedTopics)
    {
        _rules.Add(new TopicBoundaryRule(new TopicBoundaryOptions { AllowedTopics = allowedTopics.ToList() }, provider));
        return this;
    }

    /// <summary>
    /// Adds topic boundary enforcement with a custom similarity provider and threshold.
    /// </summary>
    public GuardrailPolicyBuilder EnforceTopicBoundary(ITopicSimilarityProvider provider, float similarityThreshold, params string[] allowedTopics)
    {
        _rules.Add(new TopicBoundaryRule(new TopicBoundaryOptions
        {
            AllowedTopics = allowedTopics.ToList(),
            SimilarityThreshold = similarityThreshold
        }, provider));
        return this;
    }

    /// <summary>
    /// Adds output topic boundary enforcement using keyword matching.
    /// Checks whether the agent's response stays within the allowed topics.
    /// </summary>
    public GuardrailPolicyBuilder EnforceOutputTopicBoundary(params string[] allowedTopics)
    {
        _rules.Add(new OutputTopicBoundaryRule(new OutputTopicBoundaryOptions { AllowedTopics = allowedTopics.ToList() }));
        return this;
    }

    /// <summary>
    /// Adds output topic boundary enforcement with a similarity provider (e.g. embedding-based).
    /// </summary>
    public GuardrailPolicyBuilder EnforceOutputTopicBoundary(ITopicSimilarityProvider provider, params string[] allowedTopics)
    {
        _rules.Add(new OutputTopicBoundaryRule(new OutputTopicBoundaryOptions { AllowedTopics = allowedTopics.ToList() }, provider));
        return this;
    }

    /// <summary>
    /// Adds output topic boundary enforcement with a similarity provider and threshold.
    /// </summary>
    public GuardrailPolicyBuilder EnforceOutputTopicBoundary(ITopicSimilarityProvider provider, float similarityThreshold, params string[] allowedTopics)
    {
        _rules.Add(new OutputTopicBoundaryRule(new OutputTopicBoundaryOptions
        {
            AllowedTopics = allowedTopics.ToList(),
            SimilarityThreshold = similarityThreshold
        }, provider));
        return this;
    }

    /// <summary>
    /// Adds output topic boundary enforcement with full options.
    /// </summary>
    public GuardrailPolicyBuilder EnforceOutputTopicBoundary(OutputTopicBoundaryOptions options, ITopicSimilarityProvider? provider = null)
    {
        _rules.Add(new OutputTopicBoundaryRule(options, provider));
        return this;
    }

    public GuardrailPolicyBuilder LimitInputTokens(int maxTokens, TokenOverflowStrategy strategy = TokenOverflowStrategy.Reject)
    {
        _rules.Add(new TokenLimitRule(new TokenLimitOptions { MaxTokens = maxTokens, Phase = GuardrailPhase.Input, OverflowStrategy = strategy }));
        return this;
    }

    public GuardrailPolicyBuilder LimitOutputTokens(int maxTokens, TokenOverflowStrategy strategy = TokenOverflowStrategy.Truncate)
    {
        _rules.Add(new TokenLimitRule(new TokenLimitOptions { MaxTokens = maxTokens, Phase = GuardrailPhase.Output, OverflowStrategy = strategy }));
        return this;
    }

    public GuardrailPolicyBuilder ValidateOutput(Func<string, bool> predicate, string? rejectionMessage = null)
    {
        _rules.Add(new PredicateRule("output-validation", GuardrailPhase.Output, predicate, rejectionMessage ?? "Output failed validation."));
        return this;
    }

    public GuardrailPolicyBuilder ValidateInput(Func<string, bool> predicate, string? rejectionMessage = null)
    {
        _rules.Add(new PredicateRule("input-validation", GuardrailPhase.Input, predicate, rejectionMessage ?? "Input failed validation."));
        return this;
    }

    /// <summary>
    /// Adds LLM-based prompt injection detection. More accurate than regex-based detection
    /// for sophisticated attacks (encoding tricks, indirect injection, multi-turn attacks).
    /// </summary>
    public GuardrailPolicyBuilder BlockPromptInjectionWithLlm(IChatClient chatClient, LlmPromptInjectionOptions? options = null, ChatOptions? chatOptions = null)
    {
        _rules.Add(new LlmPromptInjectionRule(chatClient, options, chatOptions));
        return this;
    }

    /// <summary>
    /// Adds LLM-based prompt injection detection with a shorter method name alias.
    /// </summary>
    public GuardrailPolicyBuilder DetectPromptInjectionWithLlm(IChatClient chatClient, LlmPromptInjectionOptions? options = null, ChatOptions? chatOptions = null)
        => BlockPromptInjectionWithLlm(chatClient, options, chatOptions);

    /// <summary>
    /// Adds LLM-based PII detection and optional redaction. More accurate than regex-based detection
    /// for unstructured PII like names, addresses, and contextual identifiers.
    /// </summary>
    public GuardrailPolicyBuilder DetectPIIWithLlm(IChatClient chatClient, LlmPiiDetectionOptions? options = null, ChatOptions? chatOptions = null)
    {
        _rules.Add(new LlmPiiDetectionRule(chatClient, options, chatOptions));
        return this;
    }

    /// <summary>
    /// Adds LLM-based topic boundary enforcement. More accurate than keyword matching —
    /// understands semantic meaning and intent.
    /// </summary>
    public GuardrailPolicyBuilder EnforceTopicBoundaryWithLlm(IChatClient chatClient, LlmTopicGuardrailOptions options, ChatOptions? chatOptions = null)
    {
        _rules.Add(new LlmTopicGuardrailRule(chatClient, options, chatOptions));
        return this;
    }

    /// <summary>
    /// Adds LLM-based topic boundary enforcement with a simple topic list.
    /// </summary>
    public GuardrailPolicyBuilder EnforceTopicBoundaryWithLlm(IChatClient chatClient, params string[] allowedTopics)
    {
        _rules.Add(new LlmTopicGuardrailRule(chatClient, new LlmTopicGuardrailOptions { AllowedTopics = allowedTopics.ToList() }));
        return this;
    }

    /// <summary>
    /// Adds LLM-based output policy enforcement. Checks if the agent's response
    /// violates a custom policy constraint (e.g. "never recommend competitors").
    /// </summary>
    public GuardrailPolicyBuilder EnforceOutputPolicy(
        IChatClient chatClient, string policyDescription, OutputPolicyAction action = OutputPolicyAction.Block, ChatOptions? chatOptions = null)
    {
        _rules.Add(new LlmOutputPolicyRule(chatClient, new LlmOutputPolicyOptions { PolicyDescription = policyDescription, Action = action }, chatOptions));
        return this;
    }

    /// <summary>
    /// Adds LLM-based output policy enforcement with full options.
    /// </summary>
    public GuardrailPolicyBuilder EnforceOutputPolicyWithLlm(IChatClient chatClient, LlmOutputPolicyOptions options, ChatOptions? chatOptions = null)
    {
        _rules.Add(new LlmOutputPolicyRule(chatClient, options, chatOptions));
        return this;
    }

    /// <summary>
    /// Adds LLM-based groundedness checking. Detects hallucinated facts and claims
    /// not supported by the conversation context.
    /// </summary>
    public GuardrailPolicyBuilder CheckGroundedness(IChatClient chatClient, LlmGroundednessOptions? options = null, ChatOptions? chatOptions = null)
    {
        _rules.Add(new LlmGroundednessRule(chatClient, options, chatOptions));
        return this;
    }

    /// <summary>
    /// Adds LLM-based groundedness checking with full options.
    /// </summary>
    public GuardrailPolicyBuilder CheckGroundednessWithLlm(IChatClient chatClient, LlmGroundednessOptions? options = null, ChatOptions? chatOptions = null)
        => CheckGroundedness(chatClient, options, chatOptions);

    /// <summary>
    /// Adds LLM-based copyright detection. Detects verbatim or near-verbatim reproduction
    /// of copyrighted material (song lyrics, book passages, articles, restrictively-licensed code).
    /// </summary>
    public GuardrailPolicyBuilder CheckCopyright(IChatClient chatClient, LlmCopyrightOptions? options = null, ChatOptions? chatOptions = null)
    {
        _rules.Add(new LlmCopyrightRule(chatClient, options, chatOptions));
        return this;
    }

    /// <summary>
    /// Adds LLM-based copyright detection with full options.
    /// </summary>
    public GuardrailPolicyBuilder CheckCopyrightWithLlm(IChatClient chatClient, LlmCopyrightOptions? options = null, ChatOptions? chatOptions = null)
        => CheckCopyright(chatClient, options, chatOptions);

    /// <summary>
    /// Adds content safety filtering. Requires an <see cref="IContentSafetyClassifier"/> to be injected
    /// via DI or passed directly via <see cref="BlockHarmfulContent(IContentSafetyClassifier, ContentSafetyOptions?)"/>.
    /// </summary>
    public GuardrailPolicyBuilder BlockHarmfulContent(ContentSafetySeverity maxAllowedSeverity = ContentSafetySeverity.Low)
    {
        _rules.Add(new ContentSafetyRule(new ContentSafetyOptions { MaxAllowedSeverity = maxAllowedSeverity }));
        return this;
    }

    /// <summary>
    /// Adds content safety filtering with full options (category filtering, blocklists).
    /// </summary>
    public GuardrailPolicyBuilder BlockHarmfulContent(ContentSafetyOptions options)
    {
        _rules.Add(new ContentSafetyRule(options));
        return this;
    }

    /// <summary>
    /// Adds content safety filtering with an explicit classifier instance and optional configuration.
    /// </summary>
    public GuardrailPolicyBuilder BlockHarmfulContent(IContentSafetyClassifier classifier, ContentSafetyOptions? options = null)
    {
        _rules.Add(new ContentSafetyRule(options, classifier));
        return this;
    }

    /// <summary>
    /// Enables progressive streaming guardrails. Instead of buffering the entire response
    /// before evaluating output rules, tokens stream through immediately while guardrails
    /// evaluate progressively. On violation, retraction/replacement events are emitted.
    /// </summary>
    public GuardrailPolicyBuilder UseProgressiveStreaming(Action<ProgressiveStreamingOptions>? configure = null)
    {
        var options = new ProgressiveStreamingOptions();
        configure?.Invoke(options);
        _progressiveStreaming = options;
        return this;
    }

    /// <summary>
    /// Enables progressive streaming guardrails with the specified options.
    /// </summary>
    public GuardrailPolicyBuilder UseProgressiveStreaming(ProgressiveStreamingOptions options)
    {
        _progressiveStreaming = options ?? throw new ArgumentNullException(nameof(options));
        return this;
    }

    public GuardrailPolicyBuilder AddRule(IGuardrailRule rule) { _rules.Add(rule); return this; }

    public GuardrailPolicyBuilder AddRule(string name, GuardrailPhase phase,
        Func<GuardrailContext, CancellationToken, ValueTask<GuardrailResult>> evaluate, int order = 100)
    {
        _rules.Add(new DelegateRule(name, phase, evaluate, order));
        return this;
    }

    public GuardrailPolicyBuilder OnViolation(Action<ViolationHandlerBuilder> configure)
    {
        var builder = new ViolationHandlerBuilder();
        configure(builder);
        _violationHandler = builder.Build();
        return this;
    }

    public IGuardrailPolicy Build() => new Guardrails.GuardrailPolicy(_name, _rules, _violationHandler, _progressiveStreaming);
}

public sealed class ViolationHandlerBuilder
{
    private IViolationHandler? _handler;

    public ViolationHandlerBuilder RejectWithMessage(string message) { _handler = new Guardrails.MessageViolationHandler(message); return this; }

    public ViolationHandlerBuilder RejectWithHandler(
        Func<GuardrailResult, GuardrailContext, CancellationToken, ValueTask<string>> handler)
    { _handler = new Guardrails.DelegateViolationHandler(handler); return this; }

    internal IViolationHandler Build() => _handler ?? new Guardrails.DefaultViolationHandler();
}

internal sealed class PredicateRule(string name, GuardrailPhase phase, Func<string, bool> predicate, string rejectionMessage) : IGuardrailRule
{
    public string Name => name;
    public GuardrailPhase Phase => phase;

    public ValueTask<GuardrailResult> EvaluateAsync(GuardrailContext context, CancellationToken cancellationToken = default)
        => ValueTask.FromResult(predicate(context.Text) ? GuardrailResult.Passed() : GuardrailResult.Blocked(rejectionMessage));
}

internal sealed class DelegateRule(string name, GuardrailPhase phase,
    Func<GuardrailContext, CancellationToken, ValueTask<GuardrailResult>> evaluate, int order) : IGuardrailRule
{
    public string Name => name;
    public GuardrailPhase Phase => phase;
    public int Order => order;

    public ValueTask<GuardrailResult> EvaluateAsync(GuardrailContext context, CancellationToken cancellationToken = default)
        => evaluate(context, cancellationToken);
}
