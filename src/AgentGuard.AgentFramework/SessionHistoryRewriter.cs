using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;

namespace AgentGuard.AgentFramework;

/// <summary>
/// Puts what the caller received in place of the response an agent saved to its session history.
/// </summary>
/// <remarks>
/// <c>ChatClientAgent</c> hands its response to its <see cref="ChatHistoryProvider"/> before any
/// <see cref="AIAgentBuilder"/> middleware sees it, so a response the output guardrails blocked or
/// rewrote would otherwise be replayed to the model, unguarded, on the next turn. Only the default
/// <see cref="InMemoryChatHistoryProvider"/> can be rewritten, and only when the saved response is found
/// at the end of the session's history.
/// </remarks>
internal static class SessionHistoryRewriter
{
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
        if (session is null || saved.Count == 0)
            return;

        // a server-side conversation keeps its history where this middleware can't reach it
        if (!string.IsNullOrEmpty(conversationId) || session is ChatClientAgentSession { ConversationId.Length: > 0 })
            return;

        if (agent.GetService<InMemoryChatHistoryProvider>() is not { } provider)
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

    private static bool IsSaved(ChatMessage stored, ChatMessage saved, bool matchByReference) =>
        matchByReference
            ? ReferenceEquals(stored, saved)
            : stored.Role == saved.Role &&
              stored.Contents.Count == saved.Contents.Count &&
              string.Equals(stored.Text, saved.Text, StringComparison.Ordinal);
}
