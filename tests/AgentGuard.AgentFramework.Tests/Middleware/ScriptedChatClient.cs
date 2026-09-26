using System.Runtime.CompilerServices;
using Microsoft.Extensions.AI;

namespace AgentGuard.AgentFramework.Tests.Middleware;

// a model that answers each call from a script: call n gets script(messages, n). Streaming replays the
// scripted response as updates, or the updates of an explicit stream script.
internal sealed class ScriptedChatClient(
    Func<IReadOnlyList<ChatMessage>, int, ChatResponse> script,
    Func<IReadOnlyList<ChatMessage>, int, IReadOnlyList<ChatResponseUpdate>>? stream = null) : IChatClient
{
    public List<List<ChatMessage>> Calls { get; } = [];

    public Task<ChatResponse> GetResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken cancellationToken = default)
    {
        var list = messages.ToList();
        Calls.Add(list);
        return Task.FromResult(script(list, Calls.Count - 1));
    }

    public async IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(
        IEnumerable<ChatMessage> messages, ChatOptions? options = null, [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        var list = messages.ToList();
        Calls.Add(list);

        var call = Calls.Count - 1;
        var updates = stream is null ? script(list, call).ToChatResponseUpdates() : stream(list, call);

        foreach (var update in updates)
        {
            await Task.Yield();
            yield return update;
        }
    }

    public object? GetService(Type serviceType, object? serviceKey = null) => null;

    public void Dispose()
    {
    }
}
