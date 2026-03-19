using AgentGuard.Core.Abstractions;
using Microsoft.Extensions.AI;

namespace AgentGuard.Core.Rules.LLM;

/// <summary>
/// Base class for guardrail rules that use an <see cref="IChatClient"/> to classify text.
/// Sends a structured prompt to the LLM and parses the response to determine pass/block/modify.
/// </summary>
public abstract class LlmGuardrailRule : IGuardrailRule
{
    private readonly IChatClient _chatClient;
    private readonly ChatOptions? _chatOptions;

    protected LlmGuardrailRule(IChatClient chatClient, ChatOptions? chatOptions = null)
    {
        _chatClient = chatClient ?? throw new ArgumentNullException(nameof(chatClient));
        _chatOptions = chatOptions;
    }

    public abstract string Name { get; }
    public abstract GuardrailPhase Phase { get; }
    public virtual int Order => 100;

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
        catch (Exception)
        {
            // Fail-open: if the LLM call fails, allow the text through
            return GuardrailResult.Passed();
        }
    }
}
