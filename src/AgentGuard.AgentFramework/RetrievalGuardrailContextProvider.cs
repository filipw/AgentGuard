using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Rules.Retrieval;
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;

namespace AgentGuard.AgentFramework;

/// <summary>
/// Options for the retrieval guardrail context provider.
/// </summary>
public sealed class RetrievalGuardrailContextProviderOptions
{
    /// <summary>
    /// The function that retrieves chunks given the user query.
    /// This is where your vector search / embedding lookup goes.
    /// </summary>
    public required Func<string, CancellationToken, Task<IReadOnlyList<RetrievedChunk>>> RetrievalFunc { get; init; }

    /// <summary>Options for the retrieval guardrail rule. Default: detect prompt injection + secrets.</summary>
    public RetrievalGuardrailOptions GuardrailOptions { get; init; } = new();

    /// <summary>
    /// How to format approved chunks into the context message.
    /// Default: joins chunks with double newlines, prefixed with "Context:".
    /// </summary>
    public Func<IReadOnlyList<RetrievedChunk>, string>? FormatContext { get; init; }

    /// <summary>
    /// Role for the injected context message. Default: System.
    /// </summary>
    public ChatRole ContextMessageRole { get; init; } = ChatRole.System;
}

/// <summary>
/// MAF <see cref="MessageAIContextProvider"/> that integrates RAG retrieval with AgentGuard guardrails.
/// Retrieves chunks via a user-supplied function, filters them through <see cref="RetrievalGuardrailRule"/>,
/// and injects approved chunks as context messages into the agent pipeline.
///
/// Usage with <see cref="AIAgentBuilder"/>:
/// <code>
/// agent.AsBuilder()
///     .UseAIContextProviders(new RetrievalGuardrailContextProvider(new()
///     {
///         RetrievalFunc = async (query, ct) => await myVectorStore.SearchAsync(query, ct)
///     }))
///     .UseAgentGuard(b => b.BlockPromptInjection())
///     .Build();
/// </code>
/// </summary>
public class RetrievalGuardrailContextProvider : MessageAIContextProvider
{
    private readonly RetrievalGuardrailContextProviderOptions _options;
    private readonly RetrievalGuardrailRule _rule;

    public RetrievalGuardrailContextProvider(RetrievalGuardrailContextProviderOptions options)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _rule = new RetrievalGuardrailRule(options.GuardrailOptions);
    }

    protected override async ValueTask<IEnumerable<ChatMessage>> ProvideMessagesAsync(
        InvokingContext context,
        CancellationToken cancellationToken)
    {
        // Extract the user query from the request messages
        var userQuery = context.RequestMessages
            .LastOrDefault(m => m.Role == ChatRole.User)?.Text;

        if (string.IsNullOrEmpty(userQuery))
            return [];

        // Retrieve chunks using the user-supplied function
        var chunks = await _options.RetrievalFunc(userQuery, cancellationToken);
        if (chunks.Count == 0)
            return [];

        // Run chunks through the retrieval guardrail
        var result = _rule.EvaluateChunks(chunks);

        if (result.ApprovedChunks.Count == 0)
            return [];

        // Format approved chunks into a context message
        var contextText = _options.FormatContext is not null
            ? _options.FormatContext(result.ApprovedChunks)
            : FormatDefaultContext(result.ApprovedChunks);

        return [new ChatMessage(_options.ContextMessageRole, contextText)];
    }

    private static string FormatDefaultContext(IReadOnlyList<RetrievedChunk> chunks)
    {
        var parts = chunks.Select((c, i) =>
        {
            var source = c.Source is not null ? $" (source: {c.Source})" : "";
            return $"[{i + 1}]{source}\n{c.Content}";
        });

        return $"Context from knowledge base:\n\n{string.Join("\n\n", parts)}";
    }
}
