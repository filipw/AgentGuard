using AgentGuard.Core.Abstractions;
using Microsoft.Extensions.AI;

namespace AgentGuard.Core.Rules.LLM;

/// <summary>
/// Base class for guardrail rules that use an <see cref="IChatClient"/> to classify text.
/// Sends a structured prompt to the LLM and parses the response to determine pass/block/modify.
/// Defaults to <see cref="StreamingEvaluationMode.FinalOnly"/> during progressive streaming
/// since LLM calls are expensive and typically need full context.
/// </summary>
public abstract class LlmGuardrailRule : IGuardrailRule, IStreamingGuardrailRule
{
    private readonly IChatClient _chatClient;
    private readonly ChatOptions? _chatOptions;
    private readonly ErrorBehavior _errorBehavior;

    protected LlmGuardrailRule(IChatClient chatClient, ChatOptions? chatOptions = null, ErrorBehavior errorBehavior = ErrorBehavior.FailOpen)
    {
        _chatClient = chatClient ?? throw new ArgumentNullException(nameof(chatClient));
        _chatOptions = chatOptions;
        _errorBehavior = errorBehavior;
    }

    public abstract string Name { get; }
    public abstract GuardrailPhase Phase { get; }
    public virtual int Order => 100;

    /// <summary>
    /// Defaults to <see cref="StreamingEvaluationMode.FinalOnly"/> since LLM calls are expensive.
    /// Override in subclasses to use <see cref="StreamingEvaluationMode.Adaptive"/> for rules
    /// where earlier detection is valuable (e.g. output policy enforcement).
    /// </summary>
    public virtual StreamingEvaluationMode StreamingMode => StreamingEvaluationMode.FinalOnly;

    /// <summary>
    /// Builds the classification prompt for the given context.
    /// The prompt should instruct the LLM to respond with a structured verdict.
    /// </summary>
    protected abstract IEnumerable<ChatMessage> BuildPrompt(GuardrailContext context);

    /// <summary>
    /// Parses the LLM response text into a <see cref="GuardrailResult"/>.
    /// </summary>
    protected abstract GuardrailResult ParseResponse(string responseText, GuardrailContext context);

    public async ValueTask<GuardrailResult> EvaluateAsync(
        GuardrailContext context, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(context.Text))
            return GuardrailResult.Passed();

        try
        {
            var messages = BuildPrompt(context).ToList();
            var response = await _chatClient.GetResponseAsync(messages, _chatOptions, cancellationToken);
            var responseText = response.Text ?? "";
            return ParseResponse(responseText, context);
        }
        catch (Exception ex)
        {
            return GuardrailResult.Error(Name, _errorBehavior, ex.Message);
        }
    }
}
