using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Text.Json.Nodes;
using AgentGuard.Core.Guardrails;
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;
using TasmanianDevil;

namespace AgentGuard.AgentFramework;

/// <summary>
/// The tool side of reversible redaction: a function-invocation middleware that calls each tool with the
/// values the tokens in its arguments stand for, and encrypts the PII in what the tool returns before the
/// model sees it.
/// </summary>
/// <remarks>
/// <para>
/// A tool is the caller's own code and the party that needs the real value, while the model only ever works
/// with tokens. The call the model made keeps its tokens: it is kept in the history and sent back to the model,
/// so only the arguments handed to the tool are restored.
/// </para>
/// <para>
/// The tokens minted for a tool result are added to the run's <see cref="PiiTokenRestorer"/>, so the response
/// and the arguments of later calls are restored from them, and recorded for the session like the request's.
/// </para>
/// </remarks>
internal sealed class PiiToolRedaction(PiiEngine engine, byte[] keyBytes)
{
    // the run the current tool invocation belongs to, established by the run wrapper
    private readonly AsyncLocal<Run?> _currentRun = new();

    /// <summary>
    /// Makes the run known to the tool invocations that happen within the calling asynchronous flow.
    /// </summary>
    /// <param name="restorer">The run's restorer.</param>
    /// <param name="session">The run's session, if it has one.</param>
    public void Begin(PiiTokenRestorer restorer, AgentSession? session) => _currentRun.Value = new Run(restorer, session);

    /// <summary>
    /// Streams the inner agent's run with the run known to the tool invocations that happen while it streams.
    /// </summary>
    /// <param name="restorer">The run's restorer.</param>
    /// <param name="session">The run's session, if it has one.</param>
    /// <param name="updates">The inner agent's updates.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The inner agent's updates, as they are.</returns>
    public async IAsyncEnumerable<AgentResponseUpdate> StreamAsync(
        PiiTokenRestorer restorer,
        AgentSession? session,
        IAsyncEnumerable<AgentResponseUpdate> updates,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var run = new Run(restorer, session);

        var enumerator = updates.GetAsyncEnumerator(cancellationToken);
        await using (enumerator.ConfigureAwait(false))
        {
            while (true)
            {
                // a value set in an async iterator does not flow past its yield, so the run is established
                // again before each step of the inner stream
                _currentRun.Value = run;
                if (!await enumerator.MoveNextAsync().ConfigureAwait(false))
                    break;

                yield return enumerator.Current;
            }
        }
    }

    /// <summary>The function-invocation middleware.</summary>
    /// <param name="agent">The agent the tool is invoked for.</param>
    /// <param name="context">The invocation.</param>
    /// <param name="next">The rest of the invocation pipeline, ending in the tool.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The tool's result, with its PII encrypted.</returns>
    public async ValueTask<object?> InvokeAsync(
        AIAgent agent,
        FunctionInvocationContext context,
        Func<FunctionInvocationContext, CancellationToken, ValueTask<object?>> next,
        CancellationToken cancellationToken)
    {
        // outside a run there are no tokens to restore, but what the tool returns is still kept from the model
        var run = _currentRun.Value;

        var arguments = context.Arguments;
        if (run is not null)
            context.Arguments = RestoreArguments(arguments, run.Restorer);

        object? result;
        try
        {
            result = await next(context, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            // only the tool gets the original values: whatever looks at the invocation afterwards sees the model's call
            context.Arguments = arguments;
        }

        return await RedactAsync(result, run, cancellationToken).ConfigureAwait(false);
    }

    private static AIFunctionArguments RestoreArguments(AIFunctionArguments arguments, PiiTokenRestorer restorer)
    {
        if (arguments.Count == 0 || !restorer.HasTokens)
            return arguments;

        Dictionary<string, object?>? restored = null;

        foreach (var (name, value) in arguments)
        {
            var restoredValue = RestoreValue(value, restorer);
            if (!ReferenceEquals(restoredValue, value))
                (restored ??= new Dictionary<string, object?>(arguments))[name] = restoredValue;
        }

        if (restored is null)
            return arguments;

        // a new dictionary: the one behind the arguments can be the model's call itself, which keeps its tokens
        return new AIFunctionArguments(restored)
        {
            Services = arguments.Services,
            Context = arguments.Context
        };
    }

    // the value with the tokens in its strings restored, at any depth; the value itself when it holds none
    private static object? RestoreValue(object? value, PiiTokenRestorer restorer)
    {
        switch (value)
        {
            case string text:
                return restorer.Restore(text);

            case JsonElement { ValueKind: JsonValueKind.String or JsonValueKind.Object or JsonValueKind.Array } element:
                return JsonNode.Parse(element.GetRawText()) is { } parsed && RestoreNode(ref parsed, restorer)
                    ? ToElement(parsed)
                    : value;

            case JsonNode node:
                var copy = node.DeepClone();
                return RestoreNode(ref copy, restorer) ? copy : value;

            case IDictionary<string, object?> dictionary:
                Dictionary<string, object?>? entries = null;
                foreach (var (key, item) in dictionary)
                {
                    var restoredItem = RestoreValue(item, restorer);
                    if (!ReferenceEquals(restoredItem, item))
                        (entries ??= new Dictionary<string, object?>(dictionary))[key] = restoredItem;
                }

                return entries ?? value;

            case IEnumerable<object?> items:
                var list = items.ToList();
                var changed = false;
                for (var i = 0; i < list.Count; i++)
                {
                    var restoredItem = RestoreValue(list[i], restorer);
                    changed |= !ReferenceEquals(restoredItem, list[i]);
                    list[i] = restoredItem;
                }

                return changed ? list : value;

            default:
                return value;
        }
    }

    // restores the strings of a JSON tree in place; true when any changed
    private static bool RestoreNode(ref JsonNode node, PiiTokenRestorer restorer)
    {
        switch (node)
        {
            case JsonValue value when value.TryGetValue<string>(out var text):
                var restored = restorer.Restore(text);
                if (ReferenceEquals(restored, text))
                    return false;

                node = JsonValue.Create(restored)!;
                return true;

            case JsonObject properties:
                var changedProperty = false;
                foreach (var (name, child) in properties.ToList())
                {
                    if (child is not { } property || !RestoreNode(ref property, restorer))
                        continue;

                    // an object or array is restored in place, and is already where it belongs
                    if (!ReferenceEquals(property, child))
                        properties[name] = property;

                    changedProperty = true;
                }

                return changedProperty;

            case JsonArray items:
                var changedItem = false;
                for (var i = 0; i < items.Count; i++)
                {
                    if (items[i] is not { } item || !RestoreNode(ref item, restorer))
                        continue;

                    if (!ReferenceEquals(item, items[i]))
                        items[i] = item;

                    changedItem = true;
                }

                return changedItem;

            default:
                return false;
        }
    }

    // what the model is given in place of a tool's result: the same result with the PII in its text encrypted
    private async ValueTask<object?> RedactAsync(object? result, Run? run, CancellationToken cancellationToken)
    {
        switch (result)
        {
            case null:
                return null;

            // images, audio and other content without text go on as they are; the text among them is encrypted
            case AIContent content and not TextContent:
                return content;

            case IEnumerable<AIContent> contents:
                return await RedactContentsAsync(contents, run, cancellationToken).ConfigureAwait(false);
        }

        // the text the model would be sent: a string as it is, anything else as JSON
        var text = GuardrailChatContent.ToText(result);
        var redacted = await RedactTextAsync(text, run, cancellationToken).ConfigureAwait(false);
        if (redacted is null)
            return result;

        return result switch
        {
            string or JsonElement { ValueKind: JsonValueKind.String } or JsonValue => redacted,
            TextContent textContent => new TextContent(redacted) { AdditionalProperties = textContent.AdditionalProperties },
            _ => AsJson(redacted)
        };
    }

    private async ValueTask<object> RedactContentsAsync(IEnumerable<AIContent> contents, Run? run, CancellationToken cancellationToken)
    {
        var items = contents.ToList();
        var changed = false;

        for (var i = 0; i < items.Count; i++)
        {
            if (items[i] is not TextContent text)
                continue;

            var redacted = await RedactTextAsync(text.Text, run, cancellationToken).ConfigureAwait(false);
            if (redacted is null)
                continue;

            items[i] = new TextContent(redacted) { AdditionalProperties = text.AdditionalProperties };
            changed = true;
        }

        return changed ? items : contents;
    }

    // the text with its PII encrypted, or null when none was found; the tokens are kept for the run and the session
    private async ValueTask<string?> RedactTextAsync(string text, Run? run, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(text))
            return null;

        var deid = await engine.DeidentifyAsync(text, cancellationToken).ConfigureAwait(false);
        if (deid.Items.Count == 0)
            return null;

        var tokens = new Dictionary<string, string>(StringComparer.Ordinal);
        PiiReversibleRedactionExtensions.AddTokens(tokens, deid.Items, keyBytes);

        if (run is not null && tokens.Count > 0)
        {
            run.Restorer.Add(tokens);

            // the session's history replays the result, tokens and all, in later turns
            if (run.Session is not null)
                PiiTokenRegistry.Record(run.Session, tokens.Keys);
        }

        // the anonymized text always goes on, even for spans an engine's non-reversible operator produced
        return deid.AnonymizedText;
    }

    // a result that was JSON stays JSON, so the model doesn't get it as a quoted string
    private static object AsJson(string text)
    {
        try
        {
            using var document = JsonDocument.Parse(text);
            return document.RootElement.Clone();
        }
        catch (JsonException)
        {
            // a token took the place of something that was not a string, such as a number: hand back the text
            return text;
        }
    }

    private static JsonElement ToElement(JsonNode node)
    {
        using var document = JsonDocument.Parse(node.ToJsonString());
        return document.RootElement.Clone();
    }

    private sealed record Run(PiiTokenRestorer Restorer, AgentSession? Session);
}
