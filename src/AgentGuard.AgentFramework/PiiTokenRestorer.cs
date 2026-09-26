using System.Buffers;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using AgentGuard.Core.Guardrails;
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;
using TasmanianDevil.Anonymizer.Operators;

namespace AgentGuard.AgentFramework;

/// <summary>
/// Restores the <c>encrypt</c> operator's tokens in the response to one invocation. Only tokens reversible
/// redaction minted are restored: the current request's, and the ones <see cref="PiiTokenRegistry"/> recorded for
/// the session.
/// </summary>
/// <remarks>
/// <para>
/// A token is found wherever it appears in the text, even run together with other letters or digits. Scanning
/// from the start, the longest token that begins at a position replaces it. The output depends only on the text,
/// not on where a stream splits it, so a streamed message comes out the same as the message in one piece.
/// </para>
/// <para>
/// The request's tokens come with their values. A recorded token is decrypted with the key the first time it
/// appears, and the value is kept for the rest of the invocation; one the key can't decrypt, such as a token
/// encrypted before the key changed, stays as it is.
/// </para>
/// </remarks>
internal sealed class PiiTokenRestorer
{
    /// <summary>The length of the shortest token: the 29 bytes of version, nonce and tag in base64url.</summary>
    public const int MinTokenLength = 39;

    // tokens are looked up by their first four characters; a shorter prefix only decides whether to wait for more
    private const int PrefixLength = 4;

    private readonly byte[] _key;
    private readonly Dictionary<string, string> _originals;
    private readonly Dictionary<ulong, List<string>> _byPrefix = [];
    private readonly HashSet<ulong> _shortPrefixes = [];
    private readonly SearchValues<char> _firstCharacters;

    /// <summary>Initializes a new instance of the <see cref="PiiTokenRestorer"/> class.</summary>
    /// <param name="key">The AES key the tokens were encrypted with.</param>
    /// <param name="requestTokens">The tokens minted for the current request, and their original values.</param>
    /// <param name="sessionTokens">The tokens recorded for the session in earlier turns.</param>
    public PiiTokenRestorer(byte[] key, IReadOnlyDictionary<string, string> requestTokens, IEnumerable<string> sessionTokens)
    {
        _key = key;
        _originals = new Dictionary<string, string>(requestTokens, StringComparer.Ordinal);

        var firstCharacters = new HashSet<char>();
        foreach (var token in requestTokens.Keys.Concat(sessionTokens))
        {
            if (IsTokenShaped(token) && Index(token))
                firstCharacters.Add(token[0]);
        }

        HasTokens = firstCharacters.Count > 0;
        _firstCharacters = SearchValues.Create([.. firstCharacters]);
    }

    /// <summary>Whether there is any token to restore.</summary>
    public bool HasTokens { get; }

    /// <summary>
    /// Restores the tokens in the text of each message of <paramref name="response"/>. A message that changes
    /// keeps its non-text content and metadata; the response keeps its ids, timestamp, usage, finish reason,
    /// continuation token and additional properties.
    /// </summary>
    /// <param name="response">The inner agent's response.</param>
    /// <returns>The response with its tokens restored, or <paramref name="response"/> itself when it has none.</returns>
    public AgentResponse Restore(AgentResponse response)
    {
        if (!HasTokens)
            return response;

        List<ChatMessage>? restored = null;

        for (var i = 0; i < response.Messages.Count; i++)
        {
            var message = response.Messages[i];
            var text = message.Text;
            if (text.Length == 0)
                continue;

            var restoredText = RestoreText(text);
            if (!string.Equals(restoredText, text, StringComparison.Ordinal))
                (restored ??= [.. response.Messages])[i] = GuardrailChatContent.WithText(message, restoredText);
        }

        if (restored is null)
            return response;

        return new AgentResponse(restored)
        {
            ResponseId = response.ResponseId,
            AgentId = response.AgentId,
            CreatedAt = response.CreatedAt,
            Usage = response.Usage,
            FinishReason = response.FinishReason,
#pragma warning disable MEAI001 // a background run's continuation token has to reach the caller
            ContinuationToken = response.ContinuationToken,
#pragma warning restore MEAI001
            AdditionalProperties = response.AdditionalProperties
        };
    }

    /// <summary>
    /// Restores the tokens in a stream of updates. Text at the end of an update that could still be the start of
    /// a token is held back until that is decided, then goes out, restored when it is a token: in the next update
    /// of its message, or in an update of its own at the end of its message, before an update that carries a
    /// guardrail event, or at the end of the stream. Every update keeps its non-text content and metadata.
    /// </summary>
    /// <param name="updates">The inner agent's updates.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The updates with their tokens restored.</returns>
    public async IAsyncEnumerable<AgentResponseUpdate> RestoreAsync(
        IAsyncEnumerable<AgentResponseUpdate> updates,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        if (!HasTokens)
        {
            await foreach (var update in updates.WithCancellation(cancellationToken).ConfigureAwait(false))
                yield return update;

            yield break;
        }

        MessageText? text = null;
        var message = default(MessageIdentity);
        AgentResponseUpdate? previous = null;

        await foreach (var update in updates.WithCancellation(cancellationToken).ConfigureAwait(false))
        {
            var startsMessage = previous is null || !message.Includes(update);

            // a progressive-streaming event corrects the text shown so far, so nothing held is carried past it
            var isGuardrailEvent =
                update.AdditionalProperties?.ContainsKey(AgentGuardMiddlewareExtensions.GuardrailEventPropertyKey) == true;

            if (startsMessage || isGuardrailEvent)
            {
                // held text belongs to the message it came from
                if (previous is not null && Flush(text, message, previous) is { } held)
                    yield return held;

                text = null;
            }

            message = startsMessage ? MessageIdentity.Start(update) : message.Continue(update);
            text ??= new MessageText(this);

            var original = update.Text;
            var restored = text.Write(original);

            if (isGuardrailEvent)
            {
                restored += text.Flush();
                text = null;
            }

            previous = update;
            yield return string.Equals(restored, original, StringComparison.Ordinal) ? update : WithText(update, restored);
        }

        if (previous is not null && Flush(text, message, previous) is { } last)
            yield return last;
    }

    private string RestoreText(string text)
    {
        var message = new MessageText(this);
        return message.Write(text) + message.Flush();
    }

    // adds a token to the index; false when it is already there
    private bool Index(string token)
    {
        var key = Pack(token.AsSpan(0, PrefixLength));
        if (!_byPrefix.TryGetValue(key, out var tokens))
            _byPrefix[key] = tokens = [];
        else if (tokens.Contains(token, StringComparer.Ordinal))
            return false;

        tokens.Add(token);
        for (var length = 1; length < PrefixLength; length++)
            _shortPrefixes.Add(Pack(token.AsSpan(0, length)));

        return true;
    }

    // what the text starting at a position is: a token, not a token, or not known until more text arrives
    private MatchResult Match(ReadOnlySpan<char> rest, bool final, out string? token)
    {
        token = null;

        var checkedLength = Math.Min(rest.Length, PrefixLength);
        for (var i = 0; i < checkedLength; i++)
        {
            if (!IsBase64Url(rest[i]))
                return MatchResult.None;
        }

        if (rest.Length < PrefixLength)
            return !final && _shortPrefixes.Contains(Pack(rest)) ? MatchResult.Undecided : MatchResult.None;

        if (!_byPrefix.TryGetValue(Pack(rest[..PrefixLength]), out var candidates))
            return MatchResult.None;

        foreach (var candidate in candidates)
        {
            if (candidate.Length <= rest.Length)
            {
                if (rest.StartsWith(candidate, StringComparison.Ordinal) && (token is null || candidate.Length > token.Length))
                    token = candidate;
            }
            else if (!final && candidate.AsSpan().StartsWith(rest, StringComparison.Ordinal))
            {
                // a longer token may still turn out to begin here
                token = null;
                return MatchResult.Undecided;
            }
        }

        return token is null ? MatchResult.None : MatchResult.Token;
    }

    // the value a token stands for, or null when the key can't decrypt it
    private string? Original(string token)
    {
        if (_originals.TryGetValue(token, out var original))
            return original;

        try
        {
            original = AesCipher.Decrypt(_key, token);
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException)
        {
            // a recorded token encrypted with another key: it stays as it is from here on
            _byPrefix[Pack(token.AsSpan(0, PrefixLength))].Remove(token);
            return null;
        }

        _originals[token] = original;
        return original;
    }

    private static bool IsTokenShaped(string token)
    {
        if (token.Length < MinTokenLength || token[0] != 'A' || !IsVersionContinuation(token[1]))
            return false;

        foreach (var c in token)
        {
            if (!IsBase64Url(c))
                return false;
        }

        return true;
    }

    private static bool IsBase64Url(char c) => char.IsAsciiLetterOrDigit(c) || c is '-' or '_';

    // after a leading 'A', the characters that complete a first byte of 0x01, the format version
    private static bool IsVersionContinuation(char c) => c is (>= 'Q' and <= 'Z') or (>= 'a' and <= 'f');

    // up to four base64url characters and their count, packed into one number
    private static ulong Pack(ReadOnlySpan<char> characters)
    {
        var packed = (ulong)characters.Length;
        for (var i = 0; i < characters.Length; i++)
            packed |= (ulong)characters[i] << (8 * (i + 1));

        return packed;
    }

    // a copy with the restored text; ToAgentResponse reads the chat update an agent update was made from,
    // and the original one still holds the tokens, so the copy is made from a new one
    private static AgentResponseUpdate WithText(AgentResponseUpdate update, string text)
    {
        var raw = update.RawRepresentation as ChatResponseUpdate;

        return new AgentResponseUpdate(new ChatResponseUpdate(update.Role, GuardrailChatContent.ReplaceText(update.Contents, text))
        {
            AuthorName = update.AuthorName,
            MessageId = update.MessageId,
            ResponseId = update.ResponseId,
            ConversationId = raw?.ConversationId,
            ModelId = raw?.ModelId,
            CreatedAt = update.CreatedAt,
            FinishReason = update.FinishReason,
            ContinuationToken = update.ContinuationToken,
            AdditionalProperties = update.AdditionalProperties
        })
        {
            AgentId = update.AgentId
        };
    }

    // the held text of a message as an update of its own, in that message
    private static AgentResponseUpdate? Flush(MessageText? text, MessageIdentity message, AgentResponseUpdate previous)
    {
        var held = text?.Flush();
        if (string.IsNullOrEmpty(held))
            return null;

        var raw = previous.RawRepresentation as ChatResponseUpdate;

        return new AgentResponseUpdate(new ChatResponseUpdate(message.Role, held)
        {
            AuthorName = message.AuthorName,
            MessageId = message.MessageId,
            ResponseId = previous.ResponseId,
            ConversationId = raw?.ConversationId,
            ModelId = raw?.ModelId,
            CreatedAt = previous.CreatedAt
        })
        {
            AgentId = previous.AgentId
        };
    }

    private enum MatchResult
    {
        None,
        Token,
        Undecided
    }

    // one message's text, restored as it arrives: text that could still be the start of a token is held back
    // until that is decided, and everything else goes out as it is written
    private sealed class MessageText(PiiTokenRestorer restorer)
    {
        private readonly StringBuilder _held = new();

        public string Write(string text)
        {
            if (text.Length == 0)
                return text;

            _held.Append(text);
            return Drain(final: false);
        }

        public string Flush() => Drain(final: true);

        private string Drain(bool final)
        {
            if (_held.Length == 0)
                return "";

            var text = _held.ToString();
            var output = new StringBuilder(text.Length);
            var position = 0;

            while (position < text.Length)
            {
                // no token begins before the next character one can begin with
                var next = text.AsSpan(position).IndexOfAny(restorer._firstCharacters);
                if (next < 0)
                {
                    output.Append(text, position, text.Length - position);
                    position = text.Length;
                    break;
                }

                output.Append(text, position, next);
                position += next;

                var result = restorer.Match(text.AsSpan(position), final, out var token);
                if (result == MatchResult.Undecided)
                    break;

                if (result == MatchResult.Token)
                {
                    // a token the key can't decrypt is dropped from the index, and the position is matched again
                    if (restorer.Original(token!) is { } original)
                    {
                        output.Append(original);
                        position += token!.Length;
                    }

                    continue;
                }

                output.Append(text[position]);
                position++;
            }

            _held.Clear().Append(text, position, text.Length - position);
            return output.ToString();
        }
    }

    // how ToAgentResponse tells a stream's messages apart: an update belongs to the current message unless it
    // names a different author, message id or role
    private readonly record struct MessageIdentity(string? AuthorName, string? MessageId, ChatRole Role)
    {
        public static MessageIdentity Start(AgentResponseUpdate update) =>
            new MessageIdentity(null, null, ChatRole.Assistant).Continue(update);

        public MessageIdentity Continue(AgentResponseUpdate update) => new(
            update.AuthorName ?? AuthorName,
            string.IsNullOrEmpty(update.MessageId) ? MessageId : update.MessageId,
            update.Role ?? Role);

        public bool Includes(AgentResponseUpdate update) =>
            !Differs(update.AuthorName, AuthorName) &&
            !Differs(update.MessageId, MessageId) &&
            (update.Role is not { } role || role == Role);

        private static bool Differs(string? value, string? current) =>
            !string.IsNullOrEmpty(value) && !string.IsNullOrEmpty(current) &&
            !string.Equals(value, current, StringComparison.Ordinal);
    }
}
