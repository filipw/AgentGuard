using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Rules.ContentSafety;
using AgentGuard.Core.Rules.PII;
using AgentGuard.Core.Rules.PromptInjection;
using AgentGuard.Core.Rules.TokenLimits;
using AgentGuard.Core.Rules.TopicBoundary;

namespace AgentGuard.Core.Builders;

public sealed class GuardrailPolicyBuilder
{
    private readonly string _name;
    private readonly List<IGuardrailRule> _rules = [];
    private IViolationHandler? _violationHandler;

    public GuardrailPolicyBuilder(string name = "default") => _name = name;

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

    public GuardrailPolicyBuilder BlockHarmfulContent(ContentSafetySeverity maxAllowedSeverity = ContentSafetySeverity.Low)
    {
        _rules.Add(new ContentSafetyRule(new ContentSafetyOptions { MaxAllowedSeverity = maxAllowedSeverity }));
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

    public IGuardrailPolicy Build() => new Guardrails.GuardrailPolicy(_name, _rules, _violationHandler);
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
