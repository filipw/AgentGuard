using System.Collections.Concurrent;
using System.Reflection;
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;

namespace AgentGuard.AgentFramework.Workflows;

/// <summary>
/// Default text extractor that handles common MAF and .NET types: a <see cref="string"/> is its own text, a
/// <see cref="ChatMessage"/> its <see cref="ChatMessage.Text"/>, a chat message collection or an
/// <see cref="AgentResponse"/> the text of each of its messages, one per line, and any other object its public
/// <c>Text</c> property, falling back to <see cref="object.ToString"/>.
/// </summary>
/// <remarks>
/// A guarded executor guards chat payloads itself, message by message, so it only asks the extractor for the
/// text of strings and other types. The chat branches serve custom extractors that delegate to this one and
/// callers that want the text of a workflow message.
/// </remarks>
public sealed class DefaultTextExtractor : ITextExtractor
{
    /// <summary>
    /// Shared singleton instance.
    /// </summary>
    public static DefaultTextExtractor Instance { get; } = new();

    private static readonly ConcurrentDictionary<Type, PropertyInfo?> _textPropertyCache = new();

    /// <inheritdoc />
    public string? ExtractText(object? message)
    {
        switch (message)
        {
            case null:
                return null;
            case string text:
                return text;
            case ChatMessage chatMessage:
                return chatMessage.Text;
            case AgentResponse agentResponse:
                return JoinText(agentResponse.Messages);
            case IEnumerable<ChatMessage> messages:
                return JoinText(messages);
        }

        // a public Text property, looked up once per type
        var textProp = _textPropertyCache.GetOrAdd(
            message.GetType(),
            static t => t.GetProperty("Text", BindingFlags.Public | BindingFlags.Instance));

        if (textProp is not null && textProp.PropertyType == typeof(string))
            return textProp.GetValue(message) as string;

        return message.ToString();
    }

    private static string JoinText(IEnumerable<ChatMessage> messages) =>
        string.Join('\n', messages.Select(m => m.Text).Where(text => text.Length > 0));
}
