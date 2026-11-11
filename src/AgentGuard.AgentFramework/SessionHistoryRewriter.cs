using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;

namespace AgentGuard.AgentFramework;

/// <summary>
/// Reads the session history an agent keeps locally, and puts what the caller received in place of the
/// response the agent saved to it.
/// </summary>
/// <remarks>
/// <para>
/// <c>ChatClientAgent</c> hands its response to its <see cref="ChatHistoryProvider"/> before any
/// <see cref="AIAgentBuilder"/> middleware sees it, so a response the output guardrails blocked or
/// rewrote would otherwise be replayed to the model, unguarded, on the next turn. Only the default
/// <see cref="InMemoryChatHistoryProvider"/> can be rewritten, and only when the saved response is found
/// at the end of the session's history.
/// </para>
/// <para>
/// The same provider is the only one whose history can be read: a middleware is given the messages of the
/// current run, while the model also answers the session's earlier turns.
/// </para>
/// </remarks>
internal static class SessionHistoryRewriter
{
    /// <summary>
    /// Returns the conversation a run continues: the session's earlier turns as they are saved, followed by
    /// <paramref name="request"/>. Call it before the agent runs, which adds the run to the history.
    /// </summary>
    /// <remarks>
    /// The request comes back as it is when there is no session, the conversation is kept server-side, the
    /// agent has no in-memory history, or the history is empty. Earlier turns the request itself starts
    /// with - a caller that passes them again - are not repeated. The history is only read.
    /// </remarks>
    /// <param name="agent">The agent that keeps the history.</param>
    /// <param name="session">The run's session.</param>
    /// <param name="request">The run's messages, as the agent is given them.</param>
    /// <returns>The conversation, or <paramref name="request"/> itself when no earlier turn can be read.</returns>
    public static IReadOnlyList<ChatMessage> WithEarlierTurns(
        AIAgent agent,
        AgentSession? session,
        IReadOnlyList<ChatMessage> request)
    {
        if (session is null || LocalHistory(agent, session, conversationId: null) is not { } provider)
            return request;

        var history = provider.GetMessages(session);
        var earlier = history.Count - Overlap(history, request);
        if (earlier <= 0)
            return request;

        // a copy: the agent adds this run to the list it keeps
        return [.. history.Take(earlier), .. request];
    }

    /// <summary>
    /// Replaces the saved response with <paramref name="delivered"/>. Nothing changes when there is no
    /// session, the conversation is kept server-side, the agent has no in-memory history, or the end of
    /// the history is not the saved response.
    /// </summary>
    /// <param name="agent">The agent that saved the response.</param>
    /// <param name="session">The run's session.</param>
    /// <param name="conversationId">The response's server-side conversation id, when it has one.</param>
    /// <param name="saved">The response messages as the agent saved them.</param>
    /// <param name="delivered">The messages the caller received instead.</param>
    /// <param name="matchByReference">
    /// Whether <paramref name="saved"/> holds the very instances the agent saved (a non-streaming run);
    /// otherwise they were rebuilt from the same updates and are compared by role and text.
    /// </param>
    public static void ReplaceSavedResponse(
        AIAgent agent,
        AgentSession? session,
        string? conversationId,
        IReadOnlyList<ChatMessage> saved,
        IReadOnlyList<ChatMessage> delivered,
        bool matchByReference)
    {
        if (session is null || saved.Count == 0 || LocalHistory(agent, session, conversationId) is not { } provider)
            return;

        var history = provider.GetMessages(session);
        var start = history.Count - saved.Count;
        if (start < 0)
            return;

        for (var i = 0; i < saved.Count; i++)
        {
            if (!IsSaved(history[start + i], saved[i], matchByReference))
                return;
        }

        provider.SetMessages(session, [.. history.Take(start), .. delivered]);
    }

    // the provider that keeps the session's history in the session itself, when that is where it is kept
    private static InMemoryChatHistoryProvider? LocalHistory(AIAgent agent, AgentSession session, string? conversationId)
    {
        // a server-side conversation keeps its history where this middleware can't reach it
        if (!string.IsNullOrEmpty(conversationId) || session is ChatClientAgentSession { ConversationId.Length: > 0 })
            return null;

        return agent.GetService<InMemoryChatHistoryProvider>();
    }

    // how many messages at the end of the history the request starts with
    private static int Overlap(List<ChatMessage> history, IReadOnlyList<ChatMessage> request)
    {
        for (var length = Math.Min(history.Count, request.Count); length > 0; length--)
        {
            var start = history.Count - length;
            var matches = true;

            for (var i = 0; i < length && matches; i++)
            {
                matches = ReferenceEquals(history[start + i], request[i]) ||
                    IsSaved(history[start + i], request[i], matchByReference: false);
            }

            if (matches)
                return length;
        }

        return 0;
    }

    private static bool IsSaved(ChatMessage stored, ChatMessage saved, bool matchByReference) =>
        matchByReference
            ? ReferenceEquals(stored, saved)
            : stored.Role == saved.Role &&
              stored.Contents.Count == saved.Contents.Count &&
              string.Equals(stored.Text, saved.Text, StringComparison.Ordinal);
}
