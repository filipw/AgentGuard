using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
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
/// <para>
/// A record or struct with a public settable (or <c>init</c>) <see cref="string"/> <c>Text</c> property is
/// rebuilt around rewritten text: a copy is made (with the record's <c>with</c> semantics) and its
/// <c>Text</c> set, so a redaction reaches the executor. Other types are not rebuilt.
/// </para>
/// <para>
/// A guarded executor guards chat payloads itself, message by message, so it only asks the extractor for the
/// text of strings and other types. The chat branches serve custom extractors that delegate to this one and
/// callers that want the text of a workflow message.
/// </para>
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

    /// <inheritdoc />
    public bool TryRebuild(object message, string text, [NotNullWhen(true)] out object? rebuilt)
    {
        ArgumentNullException.ThrowIfNull(message);

        rebuilt = null;

        var type = message.GetType();
        var textProp = _textPropertyCache.GetOrAdd(
            type,
            static t => t.GetProperty("Text", BindingFlags.Public | BindingFlags.Instance));

        if (textProp is null || textProp.PropertyType != typeof(string) || textProp.SetMethod is not { IsPublic: true })
            return false;

        // a copy, never the original: the caller may still hold the message
        var copy = _copierCache.GetOrAdd(type, static t => FindCopier(t))?.Invoke(message);
        if (copy is null)
            return false;

        textProp.SetValue(copy, text);
        rebuilt = copy;
        return true;
    }

    // a record's compiler-generated clone (what "with" calls), or a boxed struct's memberwise copy
    private static Func<object, object?>? FindCopier(Type type)
    {
        if (type.IsValueType)
        {
            var memberwiseClone = typeof(object).GetMethod("MemberwiseClone", BindingFlags.Instance | BindingFlags.NonPublic)!;
            return message => memberwiseClone.Invoke(message, null);
        }

        var clone = type.GetMethod("<Clone>$", BindingFlags.Public | BindingFlags.Instance, Type.EmptyTypes);
        return clone is null ? null : message => clone.Invoke(message, null);
    }

    private static readonly ConcurrentDictionary<Type, Func<object, object?>?> _copierCache = new();

    private static string JoinText(IEnumerable<ChatMessage> messages) =>
        string.Join('\n', messages.Select(m => m.Text).Where(text => text.Length > 0));
}
