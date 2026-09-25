using System.Text.Encodings.Web;
using System.Text.Json;
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
    /// text content is replaced: images, files, function calls and other non-text content stay, as do
    /// the role, author, message id, timestamp and additional properties.
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
    /// Tools built with <c>AIFunctionFactory</c> return their value as a <see cref="JsonElement"/>. A
    /// string value is unwrapped rather than re-serialized, so the rules see the text itself. Other
    /// values are serialized as readable JSON.
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
