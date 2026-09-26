using System.Text;
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

    /// <summary>
    /// Generic API keys, access tokens, bearer tokens, Slack tokens, and quoted secret fields such as
    /// <c>"password": "..."</c> or <c>'client_secret': '...'</c>.
    /// </summary>
    ApiKey = 1,

    /// <summary>AWS access key IDs and secret access keys.</summary>
    AwsCredential = 2,

    /// <summary>
    /// Connection strings carrying a password, and URIs with a password in their user info
    /// (<c>postgres://user:password@host</c>, <c>mongodb+srv://</c>, <c>redis://:password@</c>, ...).
    /// </summary>
    ConnectionString = 4,

    /// <summary>PEM, PGP and SSH2 private key blocks.</summary>
    PrivateKey = 8,

    /// <summary>JSON Web Tokens.</summary>
    JwtToken = 16,

    /// <summary>GitHub personal access (classic and fine-grained), OAuth, user, server and refresh tokens.</summary>
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

    /// <summary>
    /// Replacement text when redacting secrets, inserted literally. Default: [SECRET_REDACTED].
    /// </summary>
    /// <remarks>
    /// Where the secret is a value - a quoted field, the password of a connection string or URI, a
    /// token assigned to a secret-like key name - only the value is replaced, so
    /// <c>"password": "..."</c> becomes <c>"password": "[SECRET_REDACTED]"</c> and a connection URI
    /// keeps its user name and host.
    /// </remarks>
    public string Replacement { get; init; } = "[SECRET_REDACTED]";

    /// <summary>
    /// Custom patterns to match. Key is the label, value is the regex pattern. A pattern with a
    /// group named <c>secret</c> has only that group replaced when redacting; otherwise the whole
    /// match is.
    /// </summary>
    public IDictionary<string, string> CustomPatterns { get; init; } = new Dictionary<string, string>();

    /// <summary>
    /// Minimum length for generic high-entropy string detection. Default: 20. A value assigned to a
    /// secret-like key name (<c>db_password=...</c>, <c>"apiKey": "..."</c>) is considered from 12
    /// characters, or from this length when it is shorter.
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
    private const RegexOptions Options = RegexOptions.Compiled | RegexOptions.CultureInvariant;

    // the capture group a pattern uses to mark the part of its match that is the secret itself
    private const string SecretGroup = "secret";

    // a quoted value, as the secret: double or single quotes, backslash escapes allowed
    private const string QuotedValue =
        @"(?:""(?<secret>(?:[^""\\\s]|\\.)+)""|'(?<secret>(?:[^'\\\s]|\\.)+)')";

    // the user info of a URI: the user name, a colon, and the password up to the last '@' of the
    // authority (a raw '@' inside the password is common enough), followed by a host
    private const string UriUserInfo =
        @"://(?<user>[^\s:/?#@""'<>`]*):(?<secret>[^\s/?#""'<>`]+)@(?=[^\s/?#@""'<>`])";

    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(200);

    private readonly SecretsDetectionOptions _options;
    private readonly List<SecretPattern> _patterns;
    private readonly HighEntropyDetector? _highEntropy;

    /// <summary>Initializes a new instance of the <see cref="SecretsDetectionRule"/> class.</summary>
    /// <param name="options">Categories, action and custom patterns. Defaults when null.</param>
    /// <exception cref="ArgumentException"><c>MinHighEntropyLength</c> is below 8.</exception>
    public SecretsDetectionRule(SecretsDetectionOptions? options = null)
    {
        _options = options ?? new();

        if (_options.MinHighEntropyLength < 8)
            throw new ArgumentException("MinHighEntropyLength must be at least 8.", nameof(options));

        _patterns = BuildPatterns();

        _highEntropy = _options.Categories.HasFlag(SecretCategory.GenericHighEntropy)
            ? new HighEntropyDetector(_options.MinHighEntropyLength, RegexTimeout)
            : null;

        // compiled patterns generate IL on first use; pay it here, not on the first request
        RegexPatterns.Warm(Patterns);
    }

    /// <inheritdoc />
    public string Name => "secrets-detection";
    /// <inheritdoc />
    public GuardrailPhase Phase => GuardrailPhase.Both;
    /// <inheritdoc />
    public int Order => 22;

    /// <summary>Every regex the rule runs, including context gates and the high-entropy check.</summary>
    internal IEnumerable<Regex> Patterns =>
        _patterns.Select(p => p.Pattern)
            .Concat(_patterns.Select(p => p.RequiredContext).OfType<Regex>())
            .Concat(_highEntropy?.Patterns ?? []);

    /// <inheritdoc />
    public ValueTask<GuardrailResult> EvaluateAsync(GuardrailContext context, CancellationToken cancellationToken = default)
    {
        var text = context.Text;
        if (string.IsNullOrWhiteSpace(text)) return ValueTask.FromResult(GuardrailResult.Passed());

        var replacement = _options.Action == SecretAction.Redact ? _options.Replacement : null;
        var detected = new List<string>();
        var modified = text;

        foreach (var pattern in _patterns)
        {
            if (pattern.RequiredContext is not null && !pattern.RequiredContext.IsMatchOrFalse(modified))
                continue;

            if (Scan(pattern, modified, replacement, out var rewritten))
            {
                detected.Add(pattern.Label);
                modified = rewritten;
            }
        }

        if (_highEntropy is not null && _highEntropy.Scan(modified, replacement, out var withoutTokens))
        {
            detected.Add("high-entropy-string");
            modified = withoutTokens;
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

    /// <summary>
    /// Finds the matches of <paramref name="pattern"/> that its <see cref="SecretPattern.Accept"/>
    /// check lets through. With a <paramref name="replacement"/>, each one's secret - its
    /// <c>secret</c> group when the pattern has one, else the whole match - is replaced in
    /// <paramref name="rewritten"/>; without one the scan stops at the first.
    /// </summary>
    /// <remarks>
    /// A pattern that exceeds its match timeout is skipped from that point on; the other patterns
    /// still run, and whatever it already found still counts and stays replaced.
    /// </remarks>
    private static bool Scan(SecretPattern pattern, string text, string? replacement, out string rewritten)
    {
        rewritten = text;
        StringBuilder? builder = null;
        var copied = 0;
        var found = false;

        try
        {
            for (var match = pattern.Pattern.Match(text); match.Success; match = match.NextMatch())
            {
                if (pattern.Accept is not null && !pattern.Accept(match))
                    continue;

                found = true;
                if (replacement is null)
                    break;

                var secret = match.Groups[SecretGroup];
                var (start, length) = secret.Success ? (secret.Index, secret.Length) : (match.Index, match.Length);
                builder ??= new StringBuilder(text.Length);
                builder.Append(text, copied, start - copied).Append(replacement);
                copied = start + length;
            }
        }
        catch (RegexMatchTimeoutException)
        {
            // the scan could not finish inside its budget; keep what it found
        }

        if (builder is not null)
            rewritten = builder.Append(text, copied, text.Length - copied).ToString();

        return found;
    }

    private List<SecretPattern> BuildPatterns()
    {
        var p = new List<SecretPattern>();
        var c = _options.Categories;

        // AWS access key ID (AKIA...) and secret access key
        if (c.HasFlag(SecretCategory.AwsCredential))
        {
            // the leading lookbehind deliberately omits '=': it is base64 padding, so it only ever
            // trails a value, and the commonest form is KEY=<value>.
            p.Add(new("aws-access-key", Compile(@"(?<![A-Za-z0-9/+])AKIA[0-9A-Z]{16}(?![A-Za-z0-9/+=])")));
            // A bare 40-character base64 run is far too common to flag on its own, so it is gated
            // on AWS context appearing anywhere in the text, before or after the value.
            p.Add(new("aws-secret-key",
                Compile(@"(?<![A-Za-z0-9/+])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+=])"),
                Compile(@"aws|secret[_\-]?access|secret[_\-]?key", RegexOptions.IgnoreCase)));
        }

        // GitHub tokens: classic (ghp_, gho_, ghu_, ghs_, ghr_) and fine-grained personal access
        // tokens (github_pat_ and 82 characters)
        if (c.HasFlag(SecretCategory.GitHubToken))
        {
            p.Add(new("github-token", Compile(
                @"(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{82,255})(?![A-Za-z0-9_])")));
        }

        // Azure subscription keys and storage account keys
        if (c.HasFlag(SecretCategory.AzureKey))
        {
            // an Azure storage account key is 88 base64 characters ending in "==" (64 decoded bytes).
            // a SHA-512 digest in Subresource Integrity form ("sha512-" and 88 characters) has the
            // same shape, so the key cannot follow a '-'.
            p.Add(new("azure-storage-key", Compile(@"(?<![A-Za-z0-9/+-])[A-Za-z0-9/+]{86}==(?![A-Za-z0-9/+=])")));
            // Cognitive Services / APIM subscription keys are 32 lowercase hex characters.
            p.Add(new("azure-subscription-key",
                Compile(@"(?<![A-Za-z0-9])[a-f0-9]{32}(?![A-Za-z0-9])"),
                Compile(@"ocp-apim-subscription-key|azure|cognitiveservices|subscription[_\-]?key", RegexOptions.IgnoreCase)));
        }

        // JWT tokens (eyJ...). A token only starts where no base64url character precedes it, so a
        // long run of them is scanned once rather than once per "eyJ" inside it.
        if (c.HasFlag(SecretCategory.JwtToken))
        {
            p.Add(new("jwt-token", Compile(@"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")));
        }

        // Private keys (PEM, PGP, SSH2). The whole block matches, not just the header line, so
        // redaction removes the key body too.
        if (c.HasFlag(SecretCategory.PrivateKey))
        {
            p.Add(new("private-key", Compile(RegexPatterns.PemPrivateKeyBlock)));
        }

        if (c.HasFlag(SecretCategory.ApiKey))
        {
            // quoted keys with a quoted value, as in JSON, YAML flow maps and Python or JS literals
            // ("password": "...", 'client_secret': '...'). A key name ending in a secret-like word,
            // or exactly "token" (so "next_page_token" is not a secret); the name is at most 40
            // characters, which keeps the scan linear. Only the value is replaced.
            p.Add(new("secret-field",
                Compile(
                    @"(?<q>[""'])(?<name>[A-Za-z0-9_.-]{0,40}?(?:password|passwd|pwd|passphrase|secret"
                    + @"|(?:api|secret|private|access|signing|encryption|master)[_-]?key"
                    + @"|(?:access|auth|refresh|api|bearer|session|oauth|bot|id)[_-]?token)|token)\k<q>"
                    + @"[^\S\r\n]*(?::|=>?)[^\S\r\n]*" + QuotedValue,
                    RegexOptions.IgnoreCase),
                Accept: m => IsSecretValue(m.Groups[SecretGroup].ValueSpan, minLength: 6)));

            // Generic API key patterns (api_key=..., apikey:..., x-api-key:...)
            p.Add(new("api-key", Compile(@"(?i)(?:api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|bearer)\s*[:=]\s*[""']?([A-Za-z0-9_\-./+=]{20,})[""']?")));
            p.Add(new("bearer-token", Compile(@"(?i)Bearer\s+[A-Za-z0-9_\-./+=]{20,}")));
            // Slack tokens
            p.Add(new("slack-token", Compile(@"xox[bprs]-[A-Za-z0-9\-]{10,}")));
        }

        if (c.HasFlag(SecretCategory.ConnectionString))
        {
            // key=value connection strings (SQL Server, PostgreSQL, MySQL): a host key, then a
            // password key after up to 20 further ';'-terminated segments on the same line or the
            // next. Each segment is scanned once, which keeps the scan linear. Only the password
            // value is replaced.
            p.Add(new("connection-string",
                Compile(
                    @"(?<![A-Za-z0-9])(?:Server|Data[^\S\r\n]+Source|Host|Hostname)[^\S\r\n]*=[^;\r\n]*;(?:\r?\n)?"
                    + @"(?:[^;\r\n]*;(?:\r?\n)?){0,20}?[^\S\r\n]*(?:Password|Pwd)[^\S\r\n]*=[^\S\r\n]*"
                    + @"(?<secret>[^;\r\n""']*[^;\s""'])",
                    RegexOptions.IgnoreCase),
                Accept: m => IsSecretValue(m.Groups[SecretGroup].ValueSpan, minLength: 1)));

            // URIs with a password in their user info: mongodb:// and redis:// under their own
            // labels, then any other scheme (postgres, mysql, amqp, ftp, sqlserver, https, ...).
            // only the password is replaced; the user name and host stay
            p.Add(new("mongodb-uri",
                Compile(@"(?<![A-Za-z0-9+.-])mongodb(?:\+srv)?" + UriUserInfo, RegexOptions.IgnoreCase),
                Accept: m => IsSecretValue(m.Groups[SecretGroup].ValueSpan, minLength: 1)));
            p.Add(new("redis-uri",
                Compile(@"(?<![A-Za-z0-9+.-])rediss?" + UriUserInfo, RegexOptions.IgnoreCase),
                Accept: m => IsSecretValue(m.Groups[SecretGroup].ValueSpan, minLength: 1)));
            p.Add(new("connection-uri",
                Compile(@"(?<![A-Za-z0-9+.-])(?!mongodb(?:\+srv)?://|rediss?://)[A-Za-z][A-Za-z0-9+.-]{0,30}" + UriUserInfo, RegexOptions.IgnoreCase),
                Accept: m => IsSecretValue(m.Groups[SecretGroup].ValueSpan, minLength: 1)));
        }

        // Custom patterns
        foreach (var (label, pattern) in _options.CustomPatterns)
        {
            p.Add(new(label, Compile(pattern)));
        }

        return p;
    }

    private static Regex Compile(string pattern, RegexOptions extra = RegexOptions.None) =>
        new(pattern, Options | extra, RegexTimeout);

    /// <summary>
    /// Whether a value found in a secret's position is a credential: long enough, and not a
    /// placeholder, a path or a URL.
    /// </summary>
    private static bool IsSecretValue(ReadOnlySpan<char> value, int minLength) =>
        value.Length >= minLength
        && !SecretValues.IsPlaceholder(value)
        && !SecretValues.LooksLikePath(value)
        && !value.Contains("://", StringComparison.Ordinal);

    /// <summary>
    /// The Shannon entropy of <paramref name="s"/>, in bits per character.
    /// </summary>
    internal static double CalculateShannonEntropy(string s) => SecretValues.ShannonEntropy(s);

    /// <summary>A detection pattern.</summary>
    /// <param name="Label">What a match is reported as.</param>
    /// <param name="Pattern">The pattern.</param>
    /// <param name="RequiredContext">When set, the pattern only runs if this also matches somewhere in the text.</param>
    /// <param name="Accept">When set, the matches it rejects are not secrets.</param>
    private sealed record SecretPattern(string Label, Regex Pattern, Regex? RequiredContext = null, Func<Match, bool>? Accept = null);
}
