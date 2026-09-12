using System.Text.RegularExpressions;
using AgentGuard.Core.Abstractions;

namespace AgentGuard.Core.Rules.Secrets;

/// <summary>
/// Categories of secrets to detect.
/// </summary>
[Flags]
public enum SecretCategory
{
    /// <summary>No category.</summary>
    None = 0,

    /// <summary>Generic API keys, access tokens, bearer tokens, Slack tokens.</summary>
    ApiKey = 1,

    /// <summary>AWS access key IDs and secret access keys.</summary>
    AwsCredential = 2,

    /// <summary>Database connection strings carrying a password.</summary>
    ConnectionString = 4,

    /// <summary>PEM-encoded private keys.</summary>
    PrivateKey = 8,

    /// <summary>JSON Web Tokens.</summary>
    JwtToken = 16,

    /// <summary>GitHub personal access and app tokens.</summary>
    GitHubToken = 32,

    /// <summary>Azure storage account and subscription keys.</summary>
    AzureKey = 64,

    /// <summary>
    /// Any sufficiently random-looking token. Off by default: it is the highest-recall and
    /// highest-false-positive category, and the most expensive to evaluate.
    /// </summary>
    GenericHighEntropy = 128,

    /// <summary>Everything except <see cref="GenericHighEntropy"/>.</summary>
    Default = ApiKey | AwsCredential | ConnectionString | PrivateKey | JwtToken | GitHubToken | AzureKey,

    /// <summary>Every category.</summary>
    All = Default | GenericHighEntropy
}

/// <summary>
/// Action to take when secrets are detected.
/// </summary>
public enum SecretAction
{
    /// <summary>Block the entire message.</summary>
    Block,

    /// <summary>Redact detected secrets with a placeholder.</summary>
    Redact
}

/// <summary>
/// Options for the secrets detection rule.
/// </summary>
public sealed class SecretsDetectionOptions
{
    /// <summary>Categories of secrets to detect. Default: Default (all except generic high-entropy).</summary>
    public SecretCategory Categories { get; init; } = SecretCategory.Default;

    /// <summary>Action to take when a secret is detected. Default: Block.</summary>
    public SecretAction Action { get; init; } = SecretAction.Block;

    /// <summary>Replacement text when redacting secrets. Default: [SECRET_REDACTED].</summary>
    public string Replacement { get; init; } = "[SECRET_REDACTED]";

    /// <summary>Custom patterns to match. Key is the label, value is the regex pattern.</summary>
    public IDictionary<string, string> CustomPatterns { get; init; } = new Dictionary<string, string>();

    /// <summary>
    /// Minimum length for generic high-entropy string detection. Default: 20.
    /// Only applies when <see cref="SecretCategory.GenericHighEntropy"/> is enabled.
    /// </summary>
    public int MinHighEntropyLength { get; init; } = 20;
}

/// <summary>
/// Detects API keys, tokens, connection strings, private keys, and other secrets in text.
/// Runs on output by default to prevent the LLM from leaking secrets, but can also guard input.
/// Order 22 - runs after PII redaction (order 20).
/// </summary>
public sealed class SecretsDetectionRule : IGuardrailRule
{
    private readonly SecretsDetectionOptions _options;
    private readonly List<(string Label, Regex Pattern, Regex? RequiredContext)> _patterns;
    private readonly Regex? _highEntropyPattern;
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(200);

    /// <summary>Initializes a new instance of the <see cref="SecretsDetectionRule"/> class.</summary>
    /// <param name="options">Categories, action and custom patterns. Defaults when null.</param>
    /// <exception cref="ArgumentException"><c>MinHighEntropyLength</c> is below 8.</exception>
    public SecretsDetectionRule(SecretsDetectionOptions? options = null)
    {
        _options = options ?? new();

        if (_options.MinHighEntropyLength < 8)
            throw new ArgumentException("MinHighEntropyLength must be at least 8.", nameof(options));

        _patterns = BuildPatterns();

        // compiled once here rather than per evaluation; RegexOptions.Compiled emits IL, so building
        // this inside ContainsHighEntropyString cost roughly ten times the rest of the rule.
        _highEntropyPattern = _options.Categories.HasFlag(SecretCategory.GenericHighEntropy)
            ? new Regex(@"[A-Za-z0-9_\-/+=]{" + _options.MinHighEntropyLength + @",}", RegexOptions.Compiled, RegexTimeout)
            : null;
    }

    /// <inheritdoc />
    public string Name => "secrets-detection";
    /// <inheritdoc />
    public GuardrailPhase Phase => GuardrailPhase.Both;
    /// <inheritdoc />
    public int Order => 22;

    /// <inheritdoc />
    public ValueTask<GuardrailResult> EvaluateAsync(GuardrailContext context, CancellationToken cancellationToken = default)
    {
        var text = context.Text;
        if (string.IsNullOrWhiteSpace(text)) return ValueTask.FromResult(GuardrailResult.Passed());

        var detected = new List<string>();
        var modified = text;

        foreach (var (label, pattern, requiredContext) in _patterns)
        {
            if (requiredContext is not null && !requiredContext.IsMatch(modified))
                continue;

            if (pattern.IsMatch(modified))
            {
                detected.Add(label);
                if (_options.Action == SecretAction.Redact)
                {
                    // a MatchEvaluator, not the string overload: Regex.Replace treats "$" sequences
                    // in the replacement as substitutions, so a replacement containing one would be
                    // rewritten rather than inserted verbatim.
                    modified = pattern.Replace(modified, _ => _options.Replacement);
                }
            }
        }

        // Check for high-entropy strings if enabled
        if (_highEntropyPattern is not null && ContainsHighEntropyString(_highEntropyPattern, modified))
        {
            detected.Add("high-entropy-string");
        }

        if (detected.Count == 0)
            return ValueTask.FromResult(GuardrailResult.Passed());

        if (_options.Action == SecretAction.Redact)
            return ValueTask.FromResult(GuardrailResult.Modified(modified, $"Secrets detected and redacted: {string.Join(", ", detected)}"));

        return ValueTask.FromResult(new GuardrailResult
        {
            IsBlocked = true,
            Reason = $"Secrets detected in content: {string.Join(", ", detected)}",
            Severity = GuardrailSeverity.Critical,
            Metadata = new Dictionary<string, object>
            {
                ["detectedCategories"] = detected.ToArray()
            }
        });
    }

    private List<(string Label, Regex Pattern, Regex? RequiredContext)> BuildPatterns()
    {
        var p = new PatternList();
        var c = _options.Categories;

        // AWS access key ID (AKIA...) and secret access key
        if (c.HasFlag(SecretCategory.AwsCredential))
        {
            // the leading lookbehind deliberately omits '=': it is base64 padding, so it only ever
            // trails a value - excluding it here rejected the commonest form, KEY=<value>.
            p.Add(("aws-access-key", new(@"(?<![A-Za-z0-9/+])AKIA[0-9A-Z]{16}(?![A-Za-z0-9/+=])", RegexOptions.Compiled, RegexTimeout)));
            // A bare 40-character base64 run is far too common to flag on its own, so it is gated
            // on AWS context appearing anywhere in the text. The previous form used a trailing
            // lookahead, which required the keyword to come *after* the value - the opposite of how
            // "aws_secret_access_key = <value>" is actually written, so real keys went undetected.
            p.Add(("aws-secret-key",
                new(@"(?<![A-Za-z0-9/+])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+=])", RegexOptions.Compiled, RegexTimeout),
                new(@"aws|secret[_\-]?access|secret[_\-]?key", RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout)));
        }

        // GitHub tokens (ghp_, gho_, ghu_, ghs_, ghr_)
        if (c.HasFlag(SecretCategory.GitHubToken))
        {
            p.Add(("github-token", new(@"(?<![A-Za-z0-9_])gh[pousr]_[A-Za-z0-9_]{36,255}(?![A-Za-z0-9_])", RegexOptions.Compiled, RegexTimeout)));
        }

        // Azure subscription keys and storage account keys
        if (c.HasFlag(SecretCategory.AzureKey))
        {
            // An Azure storage account key is 88 base64 characters ending in "==" (64 decoded
            // bytes). The previous {44}== form could only ever match a 46-character run, which no
            // real key is, so it never fired.
            p.Add(("azure-storage-key", new(@"(?<![A-Za-z0-9/+])[A-Za-z0-9/+]{86}==(?![A-Za-z0-9/+=])", RegexOptions.Compiled, RegexTimeout)));
            // Cognitive Services / APIM subscription keys are 32 lowercase hex characters.
            p.Add(("azure-subscription-key",
                new(@"(?<![A-Za-z0-9])[a-f0-9]{32}(?![A-Za-z0-9])", RegexOptions.Compiled, RegexTimeout),
                new(@"ocp-apim-subscription-key|azure|cognitiveservices|subscription[_\-]?key", RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout)));
        }

        // JWT tokens (eyJ...)
        if (c.HasFlag(SecretCategory.JwtToken))
        {
            p.Add(("jwt-token", new(@"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", RegexOptions.Compiled, RegexTimeout)));
        }

        // Private keys (PEM format)
        if (c.HasFlag(SecretCategory.PrivateKey))
        {
            p.Add(("private-key", new(@"-----BEGIN\s+(?:RSA\s+)?(?:EC\s+)?(?:DSA\s+)?(?:OPENSSH\s+)?PRIVATE\s+KEY-----", RegexOptions.Compiled, RegexTimeout)));
        }

        // Generic API key patterns (api_key=..., apikey:..., x-api-key:...)
        if (c.HasFlag(SecretCategory.ApiKey))
        {
            p.Add(("api-key", new(@"(?i)(?:api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|bearer)\s*[:=]\s*[""']?([A-Za-z0-9_\-./+=]{20,})[""']?", RegexOptions.Compiled, RegexTimeout)));
            p.Add(("bearer-token", new(@"(?i)Bearer\s+[A-Za-z0-9_\-./+=]{20,}", RegexOptions.Compiled, RegexTimeout)));
            // Slack tokens
            p.Add(("slack-token", new(@"xox[bprs]-[A-Za-z0-9\-]{10,}", RegexOptions.Compiled, RegexTimeout)));
        }

        // Connection strings (SQL Server, PostgreSQL, MySQL, MongoDB, Redis)
        if (c.HasFlag(SecretCategory.ConnectionString))
        {
            p.Add(("connection-string", new(@"(?i)(?:Server|Data\s+Source|Host|Hostname)\s*=\s*[^;]+;\s*(?:.*?(?:Password|Pwd)\s*=\s*[^;]+)", RegexOptions.Compiled, RegexTimeout)));
            p.Add(("mongodb-uri", new(@"mongodb(?:\+srv)?://[^\s""']+:[^\s""']+@[^\s""']+", RegexOptions.Compiled, RegexTimeout)));
            p.Add(("redis-uri", new(@"redis://:[^\s""']+@[^\s""']+", RegexOptions.Compiled, RegexTimeout)));
        }

        // Custom patterns
        foreach (var (label, pattern) in _options.CustomPatterns)
        {
            p.Add((label, new(pattern, RegexOptions.Compiled, RegexTimeout)));
        }

        return p;
    }

    /// <summary>
    /// Checks for high-entropy strings that might be secrets (e.g. random tokens not matching specific patterns).
    /// Uses Shannon entropy calculation on contiguous alphanumeric sequences.
    /// </summary>
    internal static bool ContainsHighEntropyString(string text, int minLength) =>
        ContainsHighEntropyString(
            new Regex(@"[A-Za-z0-9_\-/+=]{" + minLength + @",}", RegexOptions.None, RegexTimeout), text);

    private static bool ContainsHighEntropyString(Regex tokenPattern, string text)
    {
        foreach (Match match in tokenPattern.Matches(text))
        {
            var token = match.Value;
            var entropy = CalculateShannonEntropy(token);
            // High entropy threshold: typical English ~4.0, random secrets ~5.5+
            if (entropy > 4.5) return true;
        }
        return false;
    }

    /// <summary>List of detection patterns where most entries need no context gate.</summary>
    private sealed class PatternList : List<(string Label, Regex Pattern, Regex? RequiredContext)>
    {
        public void Add((string Label, Regex Pattern) entry) => Add((entry.Label, entry.Pattern, null));
    }

    internal static double CalculateShannonEntropy(string s)
    {
        var freq = new Dictionary<char, int>();
        foreach (var ch in s)
        {
            freq.TryGetValue(ch, out var count);
            freq[ch] = count + 1;
        }

        double entropy = 0;
        var len = (double)s.Length;
        foreach (var count in freq.Values)
        {
            var p = count / len;
            entropy -= p * Math.Log2(p);
        }
        return entropy;
    }
}
