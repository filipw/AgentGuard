using System.Text.RegularExpressions;
using AgentGuard.Core.Abstractions;

namespace AgentGuard.Core.Rules.Secrets;

/// <summary>
/// Categories of secrets to detect.
/// </summary>
[Flags]
public enum SecretCategory
{
    None = 0,
    ApiKey = 1,
    AwsCredential = 2,
    ConnectionString = 4,
    PrivateKey = 8,
    JwtToken = 16,
    GitHubToken = 32,
    AzureKey = 64,
    GenericHighEntropy = 128,
    Default = ApiKey | AwsCredential | ConnectionString | PrivateKey | JwtToken | GitHubToken | AzureKey,
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
/// Order 22 — runs after PII redaction (order 20).
/// </summary>
public sealed class SecretsDetectionRule : IGuardrailRule
{
    private readonly SecretsDetectionOptions _options;
    private readonly List<(string Label, Regex Pattern)> _patterns;
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(200);

    public SecretsDetectionRule(SecretsDetectionOptions? options = null)
    {
        _options = options ?? new();
        _patterns = BuildPatterns();
    }

    public string Name => "secrets-detection";
    public GuardrailPhase Phase => GuardrailPhase.Both;
    public int Order => 22;

    public ValueTask<GuardrailResult> EvaluateAsync(GuardrailContext context, CancellationToken cancellationToken = default)
    {
        var text = context.Text;
        if (string.IsNullOrWhiteSpace(text)) return ValueTask.FromResult(GuardrailResult.Passed());

        var detected = new List<string>();
        var modified = text;

        foreach (var (label, pattern) in _patterns)
        {
            if (pattern.IsMatch(modified))
            {
                detected.Add(label);
                if (_options.Action == SecretAction.Redact)
                {
                    modified = pattern.Replace(modified, _options.Replacement);
                }
            }
        }

        // Check for high-entropy strings if enabled
        if (_options.Categories.HasFlag(SecretCategory.GenericHighEntropy))
        {
            if (ContainsHighEntropyString(modified, _options.MinHighEntropyLength))
            {
                detected.Add("high-entropy-string");
            }
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

    private List<(string, Regex)> BuildPatterns()
    {
        var p = new List<(string, Regex)>();
        var c = _options.Categories;

        // AWS access key ID (AKIA...) and secret access key
        if (c.HasFlag(SecretCategory.AwsCredential))
        {
            p.Add(("aws-access-key", new(@"(?<![A-Za-z0-9/+=])AKIA[0-9A-Z]{16}(?![A-Za-z0-9/+=])", RegexOptions.Compiled, RegexTimeout)));
            p.Add(("aws-secret-key", new(@"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])(?=.*(?:aws|secret|key))", RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout)));
        }

        // GitHub tokens (ghp_, gho_, ghu_, ghs_, ghr_)
        if (c.HasFlag(SecretCategory.GitHubToken))
        {
            p.Add(("github-token", new(@"(?<![A-Za-z0-9_])gh[pousr]_[A-Za-z0-9_]{36,255}(?![A-Za-z0-9_])", RegexOptions.Compiled, RegexTimeout)));
        }

        // Azure subscription keys and storage account keys
        if (c.HasFlag(SecretCategory.AzureKey))
        {
            p.Add(("azure-key", new(@"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{44}==(?![A-Za-z0-9/+=])", RegexOptions.Compiled, RegexTimeout)));
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
    internal static bool ContainsHighEntropyString(string text, int minLength)
    {
        // Find contiguous sequences of alphanumeric + common secret chars
        var tokenPattern = new Regex(@"[A-Za-z0-9_\-/+=]{" + minLength + @",}", RegexOptions.Compiled, RegexTimeout);
        foreach (Match match in tokenPattern.Matches(text))
        {
            var token = match.Value;
            var entropy = CalculateShannonEntropy(token);
            // High entropy threshold: typical English ~4.0, random secrets ~5.5+
            if (entropy > 4.5) return true;
        }
        return false;
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
