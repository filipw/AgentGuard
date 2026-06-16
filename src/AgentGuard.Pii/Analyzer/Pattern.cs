using System.Text.RegularExpressions;

namespace AgentGuard.Pii.Analyzer;

/// <summary>
/// A named regular expression with an associated base confidence score.
/// The compiled <see cref="Regex"/> is cached per set of options.
/// </summary>
public sealed class Pattern
{
    private Regex? _compiled;
    private RegexOptions _compiledWith;

    /// <summary>Initializes a new instance of the <see cref="Pattern"/> class.</summary>
    public Pattern(string name, string regex, double score)
    {
        Name = name;
        Regex = regex;
        Score = score;
    }

    /// <summary>The pattern's name (used in explanations).</summary>
    public string Name { get; }

    /// <summary>The regular expression source.</summary>
    public string Regex { get; }

    /// <summary>The base confidence score assigned to matches of this pattern.</summary>
    public double Score { get; }

    /// <summary>Returns a compiled <see cref="System.Text.RegularExpressions.Regex"/> for the given options, caching it.</summary>
    public Regex GetCompiled(RegexOptions options, TimeSpan timeout)
    {
        if (_compiled is null || _compiledWith != options)
        {
            _compiled = new Regex(Regex, options, timeout);
            _compiledWith = options;
        }

        return _compiled;
    }
}
