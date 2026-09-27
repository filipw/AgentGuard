using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using AgentGuard.Core.Rules.ToolCall;
using AgentGuard.Core.Rules.ToolResult;
using Microsoft.Extensions.AI;

namespace AgentGuard.Core.Guardrails;

/// <summary>
/// Helpers the adapters use to move between Microsoft.Extensions.AI content and the text and
/// property-bag entries the guardrail rules evaluate.
/// </summary>
public static class GuardrailChatContent
{
    // readable JSON for rules to scan: markup and non-ASCII text stay as written instead of escaped
    private static readonly JsonSerializerOptions ReadableJson = new(AIJsonUtilities.DefaultOptions)
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        WriteIndented = false
    };

    /// <summary>
    /// Returns a copy of <paramref name="message"/> whose text is <paramref name="text"/>. Only the
    /// text content is replaced: images, files, function calls, reasoning and other non-text content
    /// stay, as do the role, author, message id, timestamp and additional properties.
    /// </summary>
    /// <remarks>
    /// The raw provider representation is deliberately not carried over - it still holds the original
    /// text. An empty <paramref name="text"/> removes the text content altogether.
    /// </remarks>
    /// <param name="message">The message to copy.</param>
    /// <param name="text">The new text.</param>
    /// <returns>The rewritten message.</returns>
    public static ChatMessage WithText(ChatMessage message, string text)
    {
        ArgumentNullException.ThrowIfNull(message);

        return new ChatMessage(message.Role, ReplaceText(message.Contents, text))
        {
            AuthorName = message.AuthorName,
            MessageId = message.MessageId,
            CreatedAt = message.CreatedAt,
            AdditionalProperties = message.AdditionalProperties
        };
    }

    /// <summary>
    /// Replaces the text content in <paramref name="contents"/> with a single <see cref="TextContent"/>
    /// holding <paramref name="text"/>, placed where the first text content was. Every other content
    /// item keeps its position.
    /// </summary>
    /// <param name="contents">The original content items.</param>
    /// <param name="text">The new text; empty removes the text content.</param>
    /// <returns>A new content list.</returns>
    public static IList<AIContent> ReplaceText(IEnumerable<AIContent> contents, string text)
    {
        ArgumentNullException.ThrowIfNull(contents);

        var result = new List<AIContent>();
        var placed = string.IsNullOrEmpty(text);

        foreach (var content in contents)
        {
            if (content is TextContent)
            {
                if (!placed)
                {
                    result.Add(new TextContent(text));
                    placed = true;
                }

                continue;
            }

            result.Add(content);
        }

        if (!placed)
            result.Insert(0, new TextContent(text));

        return result;
    }

    /// <summary>
    /// Returns a copy of <paramref name="update"/> whose text is <paramref name="text"/>. Only the text
    /// content is replaced: function calls, usage and other non-text content stay, as do the role,
    /// author, ids, timestamp, model, finish reason, continuation token and additional properties.
    /// </summary>
    /// <remarks>
    /// The raw provider representation is not carried over, since it still holds the original text. An
    /// empty <paramref name="text"/> removes the text content altogether.
    /// </remarks>
    /// <param name="update">The update to copy.</param>
    /// <param name="text">The new text.</param>
    /// <returns>The rewritten update.</returns>
    public static ChatResponseUpdate WithText(ChatResponseUpdate update, string text)
    {
        ArgumentNullException.ThrowIfNull(update);

        return new ChatResponseUpdate(update.Role, ReplaceText(update.Contents, text))
        {
            AuthorName = update.AuthorName,
            MessageId = update.MessageId,
            ResponseId = update.ResponseId,
            ConversationId = update.ConversationId,
            CreatedAt = update.CreatedAt,
            ModelId = update.ModelId,
            FinishReason = update.FinishReason,
            ContinuationToken = update.ContinuationToken,
            AdditionalProperties = update.AdditionalProperties
        };
    }

    /// <summary>
    /// Returns the reasoning text in <paramref name="contents"/>: the text of every
    /// <see cref="TextReasoningContent"/>, concatenated. <see cref="ChatMessage.Text"/> does not include it.
    /// </summary>
    /// <param name="contents">The content items of a message or update.</param>
    /// <returns>The reasoning text, or an empty string when there is none.</returns>
    public static string GetReasoningText(IEnumerable<AIContent> contents)
    {
        ArgumentNullException.ThrowIfNull(contents);

        return string.Concat(contents.OfType<TextReasoningContent>().Select(reasoning => reasoning.Text));
    }

    /// <summary>
    /// Returns a copy of <paramref name="message"/> whose reasoning text is <paramref name="reasoningText"/>
    /// (see <see cref="ReplaceReasoningText"/>). The answer text, every other content, the role, author,
    /// message id, timestamp and additional properties stay.
    /// </summary>
    /// <param name="message">The message to copy.</param>
    /// <param name="reasoningText">The new reasoning text; empty removes it.</param>
    /// <returns>The rewritten message.</returns>
    public static ChatMessage WithReasoningText(ChatMessage message, string reasoningText)
    {
        ArgumentNullException.ThrowIfNull(message);

        return new ChatMessage(message.Role, ReplaceReasoningText(message.Contents, reasoningText))
        {
            AuthorName = message.AuthorName,
            MessageId = message.MessageId,
            CreatedAt = message.CreatedAt,
            AdditionalProperties = message.AdditionalProperties
        };
    }

    /// <summary>
    /// Replaces the reasoning text in <paramref name="contents"/> with <paramref name="reasoningText"/>,
    /// placed where the first <see cref="TextReasoningContent"/> was. Every other content item keeps its
    /// position.
    /// </summary>
    /// <remarks>
    /// Encrypted reasoning (<see cref="TextReasoningContent.ProtectedData"/>) stays on the item that carried
    /// it, with only its text replaced or removed: providers such as the OpenAI Responses API need it
    /// back to continue a tool-calling turn. A reasoning item left with neither text nor protected data is
    /// dropped.
    /// </remarks>
    /// <param name="contents">The original content items.</param>
    /// <param name="reasoningText">The new reasoning text; empty removes the reasoning text.</param>
    /// <returns>A new content list.</returns>
    public static IList<AIContent> ReplaceReasoningText(IEnumerable<AIContent> contents, string reasoningText)
    {
        ArgumentNullException.ThrowIfNull(contents);

        var result = new List<AIContent>();
        var placed = string.IsNullOrEmpty(reasoningText);

        foreach (var content in contents)
        {
            if (content is not TextReasoningContent reasoning)
            {
                result.Add(content);
                continue;
            }

            var text = placed ? "" : reasoningText;
            placed = true;

            if (text.Length == 0 && reasoning.ProtectedData is null)
                continue;

            result.Add(new TextReasoningContent(text)
            {
                ProtectedData = reasoning.ProtectedData,
                AdditionalProperties = reasoning.AdditionalProperties
            });
        }

        if (!placed)
            result.Insert(0, new TextReasoningContent(reasoningText));

        return result;
    }

    /// <summary>
    /// Makes <paramref name="answer"/> the whole text of a response: it goes into the last assistant
    /// message that has text, the other assistant messages lose their text, and a message left with no
    /// content is dropped. Non-text content and the other messages stay as they are.
    /// </summary>
    /// <remarks>
    /// Use it when one piece of text replaces everything the response said, such as a re-asked answer or
    /// the rewritten text of a progressively streamed response. When no assistant message has text, the
    /// answer is added as a new assistant message.
    /// </remarks>
    /// <param name="messages">The response's messages.</param>
    /// <param name="answer">The text that replaces the response's text.</param>
    /// <returns>A new message list.</returns>
    public static List<ChatMessage> ReplaceAnswer(IReadOnlyList<ChatMessage> messages, string answer)
    {
        ArgumentNullException.ThrowIfNull(messages);
        ArgumentNullException.ThrowIfNull(answer);

        var last = -1;
        for (var i = messages.Count - 1; i >= 0; i--)
        {
            if (IsAnswer(messages[i]))
            {
                last = i;
                break;
            }
        }

        var result = new List<ChatMessage>(messages.Count + 1);

        for (var i = 0; i < messages.Count; i++)
        {
            if (!IsAnswer(messages[i]))
            {
                result.Add(messages[i]);
                continue;
            }

            var rewritten = WithText(messages[i], i == last ? answer : "");
            if (rewritten.Contents.Count > 0)
                result.Add(rewritten);
        }

        if (last < 0 && answer.Length > 0)
            result.Add(new ChatMessage(ChatRole.Assistant, answer));

        return result;

        static bool IsAnswer(ChatMessage message) =>
            message.Role == ChatRole.Assistant && !string.IsNullOrEmpty(message.Text);
    }

    /// <summary>
    /// Builds the streaming updates that deliver <paramref name="messages"/> as <paramref name="response"/>:
    /// one update per message with its role, author, message id, timestamp, contents and additional
    /// properties, each carrying the response id, conversation id and model; then, when the response has
    /// any, one closing update with its usage, finish reason, continuation token and additional properties.
    /// </summary>
    /// <remarks>
    /// Combined with <c>ToChatResponse()</c>, the updates give back the messages (consecutive messages are
    /// told apart by their role, author or message id, as when the response was first combined from
    /// updates), the usage and the finish reason. The raw provider representations are not carried over.
    /// </remarks>
    /// <param name="response">The response whose metadata the updates carry.</param>
    /// <param name="messages">The messages to deliver, usually a rewritten form of the response's own.</param>
    /// <returns>The updates, in order.</returns>
    public static List<ChatResponseUpdate> ToUpdates(ChatResponse response, IEnumerable<ChatMessage> messages)
    {
        ArgumentNullException.ThrowIfNull(response);
        ArgumentNullException.ThrowIfNull(messages);

        var updates = new List<ChatResponseUpdate>();

        foreach (var message in messages)
        {
            updates.Add(new ChatResponseUpdate(message.Role, [.. message.Contents])
            {
                AuthorName = message.AuthorName,
                MessageId = message.MessageId,
                CreatedAt = message.CreatedAt ?? response.CreatedAt,
                AdditionalProperties = message.AdditionalProperties,
                ResponseId = response.ResponseId,
                ConversationId = response.ConversationId,
                ModelId = response.ModelId
            });
        }

        if (response.Usage is not null || response.FinishReason is not null ||
            response.ContinuationToken is not null || response.AdditionalProperties is { Count: > 0 })
        {
            // no role or message id, so it closes the last message rather than starting a new one
            var closing = new ChatResponseUpdate
            {
                ResponseId = response.ResponseId,
                ConversationId = response.ConversationId,
                ModelId = response.ModelId,
                CreatedAt = response.CreatedAt,
                FinishReason = response.FinishReason,
                ContinuationToken = response.ContinuationToken,
                AdditionalProperties = response.AdditionalProperties
            };

            if (response.Usage is { } usage)
                closing.Contents.Add(new UsageContent(usage));

            updates.Add(closing);
        }

        return updates;
    }

    /// <summary>
    /// Extracts the function calls in <paramref name="contents"/> as <see cref="AgentToolCall"/>s for
    /// <see cref="ToolCallGuardrailRule"/>.
    /// </summary>
    /// <param name="contents">Content items from one or more messages or streaming updates.</param>
    /// <returns>The tool calls, in order.</returns>
    public static List<AgentToolCall> ExtractToolCalls(IEnumerable<AIContent> contents)
    {
        ArgumentNullException.ThrowIfNull(contents);

        return contents.OfType<FunctionCallContent>()
            .Select(call => ToToolCall(call.Name ?? "", call.Arguments))
            .ToList();
    }

    /// <summary>
    /// Extracts the function results in <paramref name="contents"/> as <see cref="ToolResultEntry"/>s for
    /// <see cref="ToolResultGuardrailRule"/>. Each result is named after the call it answers (matched by
    /// call id among the same contents), so per-tool risk profiles apply; empty results are skipped.
    /// </summary>
    /// <param name="contents">Content items from one or more messages or streaming updates.</param>
    /// <returns>The tool results, in order.</returns>
    public static List<ToolResultEntry> ExtractToolResults(IEnumerable<AIContent> contents)
    {
        ArgumentNullException.ThrowIfNull(contents);

        var items = contents as IReadOnlyCollection<AIContent> ?? contents.ToList();

        var toolNames = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var call in items.OfType<FunctionCallContent>())
        {
            if (!string.IsNullOrEmpty(call.CallId) && !string.IsNullOrEmpty(call.Name))
                toolNames[call.CallId] = call.Name;
        }

        var results = new List<ToolResultEntry>();
        foreach (var result in items.OfType<FunctionResultContent>())
        {
            var content = ToText(result.Result);
            if (string.IsNullOrEmpty(content))
                continue;

            results.Add(new ToolResultEntry
            {
                ToolName = result.CallId is not null && toolNames.TryGetValue(result.CallId, out var name)
                    ? name
                    : result.CallId ?? "unknown",
                Content = content
            });
        }

        return results;
    }

    /// <summary>
    /// Builds an <see cref="AgentToolCall"/> from a tool name and its arguments, with each argument
    /// value converted by <see cref="ToText"/>.
    /// </summary>
    /// <param name="toolName">The tool being called.</param>
    /// <param name="arguments">The call's arguments, if any.</param>
    /// <returns>The tool call.</returns>
    public static AgentToolCall ToToolCall(string toolName, IEnumerable<KeyValuePair<string, object?>>? arguments)
    {
        var values = new Dictionary<string, string>();

        if (arguments is not null)
        {
            foreach (var (key, value) in arguments)
                values[key] = ToText(value);
        }

        return new AgentToolCall { ToolName = toolName, Arguments = values };
    }

    /// <summary>
    /// Converts a tool result or argument value to the text the rules should see.
    /// </summary>
    /// <remarks>
    /// Tools built with <c>AIFunctionFactory</c> return their value as a <see cref="JsonElement"/>, and
    /// Agent-Hooks hands values over as <see cref="JsonNode"/>. A string value of either is unwrapped
    /// rather than re-serialized, so the rules see the text itself. Other values are serialized as
    /// readable JSON.
    /// </remarks>
    /// <param name="value">The value.</param>
    /// <returns>The text, or an empty string for null.</returns>
    public static string ToText(object? value)
    {
        switch (value)
        {
            case null:
                return "";
            case string text:
                return text;
            case JsonElement { ValueKind: JsonValueKind.String } element:
                return element.GetString() ?? "";
            case JsonElement { ValueKind: JsonValueKind.Null or JsonValueKind.Undefined }:
                return "";
            case JsonValue jsonValue when jsonValue.TryGetValue<string>(out var jsonText):
                return jsonText;
            case TextContent textContent:
                return textContent.Text;
            case IEnumerable<AIContent> items when items.All(item => item is TextContent):
                return string.Join("\n", items.Cast<TextContent>().Select(item => item.Text));
        }

        try
        {
            return JsonSerializer.Serialize(value, value.GetType(), ReadableJson);
        }
        catch (Exception ex) when (ex is NotSupportedException or InvalidOperationException or JsonException or ArgumentException)
        {
            return value.ToString() ?? "";
        }
    }
}
