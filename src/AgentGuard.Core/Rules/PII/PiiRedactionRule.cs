using System.Text.RegularExpressions;
using AgentGuard.Core.Abstractions;

namespace AgentGuard.Core.Rules.PII;

[Flags]
public enum PiiCategory
{
    None = 0, Email = 1, Phone = 2, SSN = 4, CreditCard = 8, IpAddress = 16, DateOfBirth = 32,
    Default = Email | Phone | SSN | CreditCard,
    All = Email | Phone | SSN | CreditCard | IpAddress | DateOfBirth
}

public sealed class PiiRedactionOptions
{
    public PiiCategory Categories { get; init; } = PiiCategory.Default;
    public string Replacement { get; init; } = "[REDACTED]";
    public IDictionary<string, string> CustomPatterns { get; init; } = new Dictionary<string, string>();
    public bool RedactOutput { get; init; } = true;
}

public sealed class PiiRedactionRule : IGuardrailRule
{
    private readonly PiiRedactionOptions _options;
    private readonly List<(string Label, Regex Pattern)> _patterns;
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(200);

    public PiiRedactionRule(PiiRedactionOptions? options = null)
    {
        _options = options ?? new();
        _patterns = BuildPatterns();
    }

    public string Name => "pii-redaction";
    public GuardrailPhase Phase => _options.RedactOutput ? GuardrailPhase.Both : GuardrailPhase.Input;
    public int Order => 20;

    public ValueTask<GuardrailResult> EvaluateAsync(GuardrailContext context, CancellationToken cancellationToken = default)
    {
        var text = context.Text;
        if (string.IsNullOrWhiteSpace(text)) return ValueTask.FromResult(GuardrailResult.Passed());

        var modified = text;
        var detected = new List<string>();

        foreach (var (label, pattern) in _patterns)
        {
            if (pattern.IsMatch(modified)) { modified = pattern.Replace(modified, _options.Replacement); detected.Add(label); }
        }

        return ValueTask.FromResult(detected.Count > 0
            ? GuardrailResult.Modified(modified, $"PII detected and redacted: {string.Join(", ", detected)}")
            : GuardrailResult.Passed());
    }

    private List<(string, Regex)> BuildPatterns()
    {
        var p = new List<(string, Regex)>();
        var c = _options.Categories;
        if (c.HasFlag(PiiCategory.Email)) p.Add(("email", new(@"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", RegexOptions.Compiled, RegexTimeout)));
        if (c.HasFlag(PiiCategory.Phone)) p.Add(("phone", new(@"(?<!\d)(\+?1[\s\-.]?)?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}(?!\d)", RegexOptions.Compiled, RegexTimeout)));
        if (c.HasFlag(PiiCategory.SSN)) p.Add(("ssn", new(@"(?<!\d)\d{3}[\s\-]?\d{2}[\s\-]?\d{4}(?!\d)", RegexOptions.Compiled, RegexTimeout)));
        if (c.HasFlag(PiiCategory.CreditCard)) p.Add(("credit-card", new(@"(?<!\d)\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}(?!\d)", RegexOptions.Compiled, RegexTimeout)));
        if (c.HasFlag(PiiCategory.IpAddress)) p.Add(("ip-address", new(@"(?<!\d)(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?!\d)", RegexOptions.Compiled, RegexTimeout)));
        if (c.HasFlag(PiiCategory.DateOfBirth)) p.Add(("dob", new(@"(?i)(?:born|dob|date\s+of\s+birth)\s*:?\s*\d{1,2}[/\-\.]\d{1,2}[/\-\.]\d{2,4}", RegexOptions.Compiled, RegexTimeout)));
        foreach (var (label, pattern) in _options.CustomPatterns) p.Add((label, new(pattern, RegexOptions.Compiled, RegexTimeout)));
        return p;
    }
}
