using System.Text.Json;

namespace AgentGuard.Core.Rules.ToolCall;

/// <summary>
/// The string values inside a tool call argument that is itself JSON - an object or an array - so
/// each one can be checked the way a flat argument is.
/// </summary>
/// <remarks>
/// Checked only as JSON text, a nested value keeps its quotes, braces and escapes around it, which
/// hides it from every check that looks at where a value starts or ends, and from any check when the
/// value is written with <c>\u</c> escapes. Values are read to a fixed depth and count; a string
/// that is JSON in turn is opened once more.
/// </remarks>
internal static class JsonArgumentValues
{
    private const int MaxValues = 512;
    private const int MaxNestedDocuments = 2;

    private static readonly JsonDocumentOptions Options = new()
    {
        AllowTrailingCommas = true,
        CommentHandling = JsonCommentHandling.Skip,
        MaxDepth = 64
    };

    /// <summary>The string values in <paramref name="text"/>, or none when it is not a JSON object or array.</summary>
    internal static List<string> Find(string text)
    {
        var values = new List<string>();
        Collect(text, values, MaxNestedDocuments);
        return values;
    }

    private static void Collect(string text, List<string> values, int documentsLeft)
    {
        if (documentsLeft == 0 || !LooksLikeJsonContainer(text))
            return;

        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(text, Options);
        }
        catch (JsonException)
        {
            return;
        }

        using (document)
        {
            var pending = new Stack<JsonElement>();
            pending.Push(document.RootElement);

            while (pending.Count > 0 && values.Count < MaxValues)
            {
                var element = pending.Pop();
                switch (element.ValueKind)
                {
                    case JsonValueKind.Object:
                        foreach (var property in element.EnumerateObject())
                            pending.Push(property.Value);
                        break;

                    case JsonValueKind.Array:
                        foreach (var item in element.EnumerateArray())
                            pending.Push(item);
                        break;

                    case JsonValueKind.String:
                        var value = element.GetString();
                        if (!string.IsNullOrWhiteSpace(value))
                        {
                            values.Add(value);
                            Collect(value, values, documentsLeft - 1);
                        }

                        break;
                }
            }
        }
    }

    private static bool LooksLikeJsonContainer(string text)
    {
        var trimmed = text.AsSpan().Trim();
        return trimmed.Length >= 2
            && ((trimmed[0] == '{' && trimmed[^1] == '}') || (trimmed[0] == '[' && trimmed[^1] == ']'));
    }
}
