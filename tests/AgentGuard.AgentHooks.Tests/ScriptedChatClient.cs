using System.Runtime.CompilerServices;
using Microsoft.Extensions.AI;

namespace AgentGuard.AgentHooks.Tests;

// a model that answers each call from a script: call n gets script(messages, n); streaming replays the
// scripted response as updates
internal sealed class ScriptedChatClient(Func<IReadOnlyList<ChatMessage>, int, ChatResponse> script) : IChatClient
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

        foreach (var update in script(list, Calls.Count - 1).ToChatResponseUpdates())
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
