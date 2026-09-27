using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.AI;

namespace AgentGuard.AgentHooks;

/// <summary>
/// Moves chat messages between the Agent-Hooks wire form (<c>{ "role", "content" }</c>, content being
/// a string for plain text or a list of serialized content items) and Microsoft.Extensions.AI messages,
/// so the interceptor can guard them with the same code as the other integrations.
/// </summary>
/// <remarks>
/// Content is serialized the way the Agent Framework's Agent-Hooks support projects it. A message the
/// rules leave alone is written back as the JSON it arrived as, so the host matches it to its original
/// and keeps that original - metadata and all.
/// </remarks>
internal static class HookMessages
{
    private static readonly JsonSerializerOptions JsonOptions = AIJsonUtilities.DefaultOptions;

    /// <summary>Reads the messages of a wire message list, with the JSON each one came from.</summary>
    public static (List<ChatMessage> Messages, List<JsonObject> Sources) ReadMessages(JsonArray array)
    {
        var messages = new List<ChatMessage>(array.Count);
        var sources = new List<JsonObject>(array.Count);

        foreach (var item in array)
        {
            if (item is not JsonObject wire)
                continue;

            messages.Add(ReadMessage(wire));
            sources.Add(wire);
        }

        return (messages, sources);
    }

    /// <summary>Reads one wire message.</summary>
    public static ChatMessage ReadMessage(JsonObject wire) =>
        new(new ChatRole(RoleOf(wire)), ReadContents(wire["content"]));

    /// <summary>The role of a wire message, or <paramref name="fallback"/> when it has none.</summary>
    public static string RoleOf(JsonObject wire, string fallback = "user") =>
        wire["role"] is JsonValue value && value.TryGetValue<string>(out var role) && !string.IsNullOrEmpty(role) ? role : fallback;

    /// <summary>Reads wire content: a string, one content item or a list of them.</summary>
    public static List<AIContent> ReadContents(JsonNode? content) => content switch
    {
        null => [],
        JsonValue value when value.TryGetValue<string>(out var text) => [new TextContent(text)],
        JsonArray items => [.. items.Select(ReadContent)],
        _ => [ReadContent(content)]
    };

    /// <summary>Writes content the way the host projects it: plain text as a string, anything else as a list.</summary>
    public static JsonNode? WriteContents(IList<AIContent> contents)
    {
        if (contents.Count == 1 && contents[0] is TextContent text)
            return JsonValue.Create(text.Text ?? string.Empty);

        var array = new JsonArray();
        foreach (var content in contents)
        {
            array.Add(content is OpaqueContent opaque
                ? opaque.Json?.DeepClone()
                : JsonSerializer.SerializeToNode<AIContent>(content, JsonOptions));
        }

        return array;
    }

    /// <summary>Writes one message.</summary>
    public static JsonObject WriteMessage(ChatMessage message) => new()
    {
        ["role"] = message.Role.Value,
        ["content"] = WriteContents(message.Contents)
    };

    /// <summary>
    /// Writes <paramref name="messages"/> as a wire list. A message that is one of
    /// <paramref name="originals"/> (the same instance) is written as the JSON it came from.
    /// </summary>
    public static JsonArray WriteMessages(
        IReadOnlyList<ChatMessage> messages, IReadOnlyList<ChatMessage> originals, IReadOnlyList<JsonObject> sources)
    {
        var array = new JsonArray();

        foreach (var message in messages)
        {
            var index = IndexOf(originals, message);
            array.Add(index >= 0 ? sources[index].DeepClone() : WriteMessage(message));
        }

        return array;
    }

    private static int IndexOf(IReadOnlyList<ChatMessage> messages, ChatMessage message)
    {
        for (var i = 0; i < messages.Count; i++)
        {
            if (ReferenceEquals(messages[i], message))
                return i;
        }

        return -1;
    }

    private static AIContent ReadContent(JsonNode? item)
    {
        if (item is JsonValue value && value.TryGetValue<string>(out var text))
            return new TextContent(text);

        if (item is JsonObject content && content.ContainsKey("$type"))
        {
            try
            {
                if (JsonSerializer.Deserialize<AIContent>(content, JsonOptions) is { } decoded)
                    return decoded;
            }
            catch (Exception ex) when (ex is JsonException or NotSupportedException)
            {
                // kept as it came, below
            }
        }

        // content this library can't read goes back exactly as it came
        return new OpaqueContent(item?.DeepClone());
    }
}

/// <summary>A content item read from the wire that has no Microsoft.Extensions.AI type; written back unchanged.</summary>
internal sealed class OpaqueContent(JsonNode? json) : AIContent
{
    /// <summary>The item as it arrived.</summary>
    public JsonNode? Json { get; } = json;
}
