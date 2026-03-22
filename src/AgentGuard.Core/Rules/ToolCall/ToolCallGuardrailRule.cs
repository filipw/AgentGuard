using System.Text.RegularExpressions;
using AgentGuard.Core.Abstractions;

namespace AgentGuard.Core.Rules.ToolCall;

/// <summary>
/// Categories of tool call injection to detect.
/// </summary>
[Flags]
public enum ToolCallInjectionCategory
{
    None = 0,

    /// <summary>SQL injection patterns (UNION SELECT, DROP TABLE, OR 1=1, etc.).</summary>
    SqlInjection = 1,

    /// <summary>Code injection patterns (eval, exec, subprocess, os.system, etc.).</summary>
    CodeInjection = 2,

    /// <summary>Path traversal patterns (../, %2e%2e, etc.).</summary>
    PathTraversal = 4,

    /// <summary>Command injection patterns (;, |, $(), backticks, etc.).</summary>
    CommandInjection = 8,

    /// <summary>SSRF patterns (internal IPs, localhost, metadata endpoints).</summary>
    Ssrf = 16,

    /// <summary>Template injection patterns (Jinja2, Handlebars, etc.).</summary>
    TemplateInjection = 32,

    /// <summary>XSS patterns in tool arguments.</summary>
    Xss = 64,

    Default = SqlInjection | CodeInjection | PathTraversal | CommandInjection | Ssrf,
    All = SqlInjection | CodeInjection | PathTraversal | CommandInjection | Ssrf | TemplateInjection | Xss
}

/// <summary>
/// Represents a tool call made by an agent that should be inspected.
/// </summary>
public sealed class AgentToolCall
{
    /// <summary>The name of the tool being called.</summary>
    public required string ToolName { get; init; }

    /// <summary>The arguments as key-value pairs. Values are the string representation.</summary>
    public required IReadOnlyDictionary<string, string> Arguments { get; init; }

    /// <summary>Optional raw JSON or string representation of the full call.</summary>
    public string? RawContent { get; init; }
}

/// <summary>
/// Result of evaluating a single tool call argument.
/// </summary>
public sealed class ToolCallViolation
{
    /// <summary>The tool name.</summary>
    public required string ToolName { get; init; }

    /// <summary>The argument name that contained the injection.</summary>
    public required string ArgumentName { get; init; }

    /// <summary>The category of injection detected.</summary>
    public required ToolCallInjectionCategory Category { get; init; }

    /// <summary>Description of what was detected.</summary>
    public required string Description { get; init; }
}

/// <summary>
/// Options for the tool call guardrail rule.
/// </summary>
public sealed class ToolCallGuardrailOptions
{
    /// <summary>Categories of injection to detect. Default: Default (SQL, Code, Path, Command, SSRF).</summary>
    public ToolCallInjectionCategory Categories { get; init; } = ToolCallInjectionCategory.Default;

    /// <summary>
    /// Tool names to skip (whitelist). Useful for tools that legitimately accept code/SQL.
    /// Default: empty (all tools are checked).
    /// </summary>
    public ISet<string> AllowedTools { get; init; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Argument names to skip across all tools (e.g. "code" for a code execution tool).
    /// Default: empty.
    /// </summary>
    public ISet<string> AllowedArguments { get; init; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Per-tool argument allowlists. Key is tool name, value is set of argument names to skip.
    /// More granular than <see cref="AllowedTools"/> or <see cref="AllowedArguments"/>.
    /// </summary>
    public IDictionary<string, ISet<string>> PerToolAllowedArguments { get; init; } = new Dictionary<string, ISet<string>>(StringComparer.OrdinalIgnoreCase);
}

/// <summary>
/// Guards against injection attacks in agent tool calls. Inspects tool call arguments
/// for SQL injection, code injection, path traversal, command injection, SSRF, template
/// injection, and XSS patterns.
///
/// This rule operates on the <see cref="GuardrailContext.Properties"/> bag - callers place
/// tool calls under the <c>ToolCalls</c> key. The rule evaluates each argument of each
/// tool call and blocks if any injection pattern is detected.
///
/// Order 45 - runs after content rules but before content safety (order 50).
/// </summary>
public sealed class ToolCallGuardrailRule : IGuardrailRule
{
    private readonly ToolCallGuardrailOptions _options;
    private readonly Dictionary<ToolCallInjectionCategory, List<(string Description, Regex Pattern)>> _patterns;

    /// <summary>Well-known property key for tool calls in GuardrailContext.Properties.</summary>
    public const string ToolCallsKey = "ToolCalls";

    /// <summary>Well-known property key for violations found.</summary>
    public const string ViolationsKey = "ToolCallViolations";

    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(200);

    public ToolCallGuardrailRule(ToolCallGuardrailOptions? options = null)
    {
        _options = options ?? new();
        _patterns = BuildPatterns();
    }

    public string Name => "tool-call-guardrail";
    public GuardrailPhase Phase => GuardrailPhase.Output;
    public int Order => 45;

    public ValueTask<GuardrailResult> EvaluateAsync(GuardrailContext context, CancellationToken cancellationToken = default)
    {
        if (!context.Properties.TryGetValue(ToolCallsKey, out var callsObj) ||
            callsObj is not IReadOnlyList<AgentToolCall> toolCalls ||
            toolCalls.Count == 0)
        {
            return ValueTask.FromResult(GuardrailResult.Passed());
        }

        var violations = new List<ToolCallViolation>();

        foreach (var call in toolCalls)
        {
            // Skip whitelisted tools
            if (_options.AllowedTools.Contains(call.ToolName))
                continue;

            var perToolAllowed = _options.PerToolAllowedArguments.TryGetValue(call.ToolName, out var allowed)
                ? allowed
                : null;

            foreach (var (argName, argValue) in call.Arguments)
            {
                // Skip whitelisted arguments
                if (_options.AllowedArguments.Contains(argName))
                    continue;
                if (perToolAllowed?.Contains(argName) == true)
                    continue;

                if (string.IsNullOrWhiteSpace(argValue))
                    continue;

                // Check each enabled category
                foreach (var (category, patterns) in _patterns)
                {
                    foreach (var (description, pattern) in patterns)
                    {
                        if (pattern.IsMatch(argValue))
                        {
                            violations.Add(new ToolCallViolation
                            {
                                ToolName = call.ToolName,
                                ArgumentName = argName,
                                Category = category,
                                Description = description
                            });
                            goto nextArg; // One violation per argument is enough
                        }
                    }
                }
                nextArg:;
            }

            // Also check raw content if available
            if (call.RawContent is { Length: > 0 } rawContent)
            {
                foreach (var (category, patterns) in _patterns)
                {
                    foreach (var (description, pattern) in patterns)
                    {
                        if (pattern.IsMatch(rawContent))
                        {
                            violations.Add(new ToolCallViolation
                            {
                                ToolName = call.ToolName,
                                ArgumentName = "_raw",
                                Category = category,
                                Description = description
                            });
                            goto nextCall;
                        }
                    }
                }
                nextCall:;
            }
        }

        if (violations.Count > 0)
        {
            context.Properties[ViolationsKey] = violations;

            var first = violations[0];
            return ValueTask.FromResult(new GuardrailResult
            {
                IsBlocked = true,
                Reason = $"Tool call injection detected in {first.ToolName}.{first.ArgumentName}: {first.Description}",
                Severity = GuardrailSeverity.Critical,
                Metadata = new Dictionary<string, object>
                {
                    ["violationCount"] = violations.Count,
                    ["toolName"] = first.ToolName,
                    ["argumentName"] = first.ArgumentName,
                    ["category"] = first.Category.ToString(),
                    ["violations"] = violations.Select(v => $"{v.ToolName}.{v.ArgumentName}: {v.Description}").ToArray()
                }
            });
        }

        return ValueTask.FromResult(GuardrailResult.Passed());
    }

    private Dictionary<ToolCallInjectionCategory, List<(string, Regex)>> BuildPatterns()
    {
        var result = new Dictionary<ToolCallInjectionCategory, List<(string, Regex)>>();
        var c = _options.Categories;

        if (c.HasFlag(ToolCallInjectionCategory.SqlInjection))
        {
            result[ToolCallInjectionCategory.SqlInjection] =
            [
                ("SQL UNION injection", new(@"(?i)\bUNION\s+(ALL\s+)?SELECT\b", RegexOptions.Compiled, RegexTimeout)),
                ("SQL DROP injection", new(@"(?i)\bDROP\s+(TABLE|DATABASE|INDEX)\b", RegexOptions.Compiled, RegexTimeout)),
                ("SQL tautology injection", new(@"(?i)(?:'\s*OR\s+['""]?[^'""]+'?\s*=\s*['""]?|'\s*OR\s+1\s*=\s*1|'\s*OR\s+TRUE)", RegexOptions.Compiled, RegexTimeout)),
                ("SQL comment injection", new(@"(?:--|#|/\*)\s*$", RegexOptions.Compiled | RegexOptions.Multiline, RegexTimeout)),
                ("SQL INSERT/UPDATE injection", new(@"(?i)\b(?:INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b", RegexOptions.Compiled, RegexTimeout)),
                ("SQL EXEC injection", new(@"(?i)\b(?:EXEC(?:UTE)?|xp_cmdshell|sp_executesql)\b", RegexOptions.Compiled, RegexTimeout)),
                ("SQL batch terminator", new(@";\s*(?i)(?:SELECT|DROP|INSERT|UPDATE|DELETE|EXEC|UNION|ALTER|CREATE)\b", RegexOptions.Compiled, RegexTimeout)),
            ];
        }

        if (c.HasFlag(ToolCallInjectionCategory.CodeInjection))
        {
            result[ToolCallInjectionCategory.CodeInjection] =
            [
                ("Python code injection", new(@"(?i)\b(?:eval|exec|compile|__import__|os\.system|subprocess\.(?:call|run|Popen)|importlib)\s*\(", RegexOptions.Compiled, RegexTimeout)),
                ("JavaScript code injection", new(@"(?i)\b(?:eval|Function|setTimeout|setInterval)\s*\(", RegexOptions.Compiled, RegexTimeout)),
                ("Shell code injection via Python", new(@"(?i)\bos\.(?:system|popen|exec[lv]?[pe]?)\s*\(", RegexOptions.Compiled, RegexTimeout)),
                ("Pickle deserialization", new(@"(?i)\b(?:pickle\.loads|yaml\.(?:load|unsafe_load)|marshal\.loads)\s*\(", RegexOptions.Compiled, RegexTimeout)),
                (".NET code injection", new(@"(?i)\b(?:Process\.Start|Assembly\.Load|Activator\.CreateInstance|Type\.InvokeMember)\s*\(", RegexOptions.Compiled, RegexTimeout)),
            ];
        }

        if (c.HasFlag(ToolCallInjectionCategory.PathTraversal))
        {
            result[ToolCallInjectionCategory.PathTraversal] =
            [
                ("Directory traversal (../)", new(@"(?:\.\.[\\/]){2,}", RegexOptions.Compiled, RegexTimeout)),
                ("Encoded directory traversal", new(@"(?:%2[eE]){2}[\\/]", RegexOptions.Compiled, RegexTimeout)),
                ("Absolute path to sensitive files", new(@"(?i)(?:/etc/(?:passwd|shadow|hosts)|/proc/self/|C:\\Windows\\System32)", RegexOptions.Compiled, RegexTimeout)),
                ("Null byte injection", new(@"%00|\\x00|\\0", RegexOptions.Compiled, RegexTimeout)),
            ];
        }

        if (c.HasFlag(ToolCallInjectionCategory.CommandInjection))
        {
            result[ToolCallInjectionCategory.CommandInjection] =
            [
                ("Shell command chaining", new(@"[;&|]{1,2}\s*(?:cat|ls|whoami|id|curl|wget|nc|ncat|bash|sh|powershell|cmd)\b", RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout)),
                ("Command substitution", new(@"\$\([^)]+\)|`[^`]+`", RegexOptions.Compiled, RegexTimeout)),
                ("Pipe to shell", new(@"\|\s*(?:bash|sh|zsh|cmd|powershell)\b", RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout)),
                ("Reverse shell patterns", new(@"(?i)(?:bash\s+-i\s+>&|/dev/tcp/|nc\s+-[elp]|mkfifo|ncat\s.*?-e)", RegexOptions.Compiled, RegexTimeout)),
            ];
        }

        if (c.HasFlag(ToolCallInjectionCategory.Ssrf))
        {
            result[ToolCallInjectionCategory.Ssrf] =
            [
                ("Localhost SSRF", new(@"(?i)(?:https?://)?(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])(?:[:/]|$)", RegexOptions.Compiled, RegexTimeout)),
                ("Internal network SSRF", new(@"(?i)(?:https?://)?(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?:[:/]|$)", RegexOptions.Compiled, RegexTimeout)),
                ("Cloud metadata SSRF", new(@"(?i)(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200)", RegexOptions.Compiled, RegexTimeout)),
                ("DNS rebinding via special TLDs", new(@"(?i)(?:https?://)?[a-z0-9.-]*\.(?:internal|local|localhost|corp)(?:[:/]|$)", RegexOptions.Compiled, RegexTimeout)),
            ];
        }

        if (c.HasFlag(ToolCallInjectionCategory.TemplateInjection))
        {
            result[ToolCallInjectionCategory.TemplateInjection] =
            [
                ("Jinja2/Python template injection", new(@"\{\{.*?(?:config|self|request|lipsum|cycler|joiner|namespace|__class__|__mro__|__subclasses__).*?\}\}", RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout)),
                ("Server-side template injection", new(@"\$\{.*?(?:Runtime|getClass|forName|exec|ProcessBuilder).*?\}", RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout)),
                ("Handlebars injection", new(@"\{\{(?:#each|#if|#with|lookup|helper)\b", RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout)),
                ("Expression language injection", new(@"#\{.*?\}", RegexOptions.Compiled, RegexTimeout)),
            ];
        }

        if (c.HasFlag(ToolCallInjectionCategory.Xss))
        {
            result[ToolCallInjectionCategory.Xss] =
            [
                ("Script tag XSS", new(@"<\s*script\b[^>]*>", RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout)),
                ("Event handler XSS", new(@"(?i)\bon(?:error|load|click|mouseover|focus|blur|submit|change|input|keyup|keydown)\s*=", RegexOptions.Compiled, RegexTimeout)),
                ("JavaScript protocol XSS", new(@"(?i)javascript\s*:", RegexOptions.Compiled, RegexTimeout)),
                ("Data URI XSS", new(@"(?i)data\s*:\s*text/html", RegexOptions.Compiled, RegexTimeout)),
                ("SVG XSS", new(@"<\s*svg\b[^>]*\bon\w+\s*=", RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout)),
            ];
        }

        return result;
    }
}
