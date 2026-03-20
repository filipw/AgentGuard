using System.Collections.Concurrent;
using System.Reflection;
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;

namespace AgentGuard.Workflows;

/// <summary>
/// Default text extractor that handles common MAF and .NET types.
/// Falls back to ToString() for unknown types.
/// </summary>
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
        if (message is null)
            return null;

        // Direct string
        if (message is string s)
            return s;

        // Microsoft.Extensions.AI ChatMessage
        if (message is ChatMessage chatMessage)
            return chatMessage.Text;

        // MAF AgentResponse — extract last assistant message text
        if (message is AgentResponse agentResponse)
        {
            return agentResponse.Messages
                .Where(m => m.Role == ChatRole.Assistant)
                .Select(m => m.Text)
                .LastOrDefault();
        }

        // IEnumerable<ChatMessage> — last message text
        if (message is IEnumerable<ChatMessage> messages)
            return messages.LastOrDefault()?.Text;

        // Reflection: look for a public Text property (cached)
        var textProp = _textPropertyCache.GetOrAdd(
            message.GetType(),
            static t => t.GetProperty("Text", BindingFlags.Public | BindingFlags.Instance));

        if (textProp is not null && textProp.PropertyType == typeof(string))
            return textProp.GetValue(message) as string;

        // Fallback
        return message.ToString();
    }
}
