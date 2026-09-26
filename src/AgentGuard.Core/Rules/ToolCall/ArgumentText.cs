namespace AgentGuard.Core.Rules.ToolCall;

/// <summary>
/// A tool call argument value and the percent-decoded forms it is also checked in, so an injection
/// hidden behind one or more layers of URL encoding (<c>%2e%2e%2f</c>, <c>%252e</c>, <c>%0a</c>) is
/// seen the way the tool that decodes it will see it.
/// </summary>
/// <remarks>Decoding runs on first use and at most <see cref="MaxDecodeRounds"/> times.</remarks>
internal sealed class ArgumentText(string raw)
{
    /// <summary>How many layers of percent-encoding are peeled off.</summary>
    internal const int MaxDecodeRounds = 3;

    private List<string>? _decoded;

    /// <summary>The value as written.</summary>
    internal string Raw { get; } = raw;

    /// <summary>The value with each layer of percent-encoding removed, outermost first; empty when nothing decodes.</summary>
    internal List<string> Decoded => _decoded ??= PercentDecoder.DecodeLayers(Raw, MaxDecodeRounds);

    /// <summary>Whether <paramref name="test"/> holds for the value as written or for any decoded form.</summary>
    internal bool AnyForm(Func<string, bool> test)
    {
        if (test(Raw))
            return true;

        foreach (var decoded in Decoded)
        {
            if (test(decoded))
                return true;
        }

        return false;
    }

    /// <summary>
    /// The first non-null result of <paramref name="find"/> for the value as written, then for each
    /// decoded form.
    /// </summary>
    internal string? FirstFound(Func<string, string?> find)
    {
        if (find(Raw) is { } found)
            return found;

        foreach (var decoded in Decoded)
        {
            if (find(decoded) is { } decodedFound)
                return decodedFound;
        }

        return null;
    }
}
