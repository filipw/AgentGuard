using System.Text.RegularExpressions;
using AgentGuard.Core.Abstractions;

namespace AgentGuard.Core.Rules.ToolCall;

/// <summary>
/// Categories of tool call injection to detect.
/// </summary>
[Flags]
public enum ToolCallInjectionCategory
{
    /// <summary>No category.</summary>
    None = 0,

    /// <summary>SQL injection patterns (UNION SELECT, DROP TABLE, quoted and unquoted tautologies such as OR 1=1, etc.).</summary>
    SqlInjection = 1,

    /// <summary>Code injection patterns (eval, exec, subprocess, os.system, etc.).</summary>
    CodeInjection = 2,

    /// <summary>
    /// Path traversal patterns: ../ and ..\ in any mix, their percent-encoded, double-encoded and
    /// overlong UTF-8 forms, absolute paths to sensitive files, and NUL bytes.
    /// </summary>
    PathTraversal = 4,

    /// <summary>
    /// Command injection patterns: commands chained with ;, &amp;, &amp;&amp;, ||, | or a line break
    /// (also percent-encoded), $() and backtick substitution, pipes to a shell, reverse shells.
    /// </summary>
    CommandInjection = 8,

    /// <summary>
    /// SSRF targets: loopback, unspecified, private, link-local and cloud metadata addresses in any
    /// IPv4 or IPv6 notation, and internal host names (localhost, .internal, .local, ...).
    /// </summary>
    Ssrf = 16,

    /// <summary>Template injection patterns (Jinja2, Handlebars, etc.).</summary>
    TemplateInjection = 32,

    /// <summary>XSS patterns in tool arguments.</summary>
    Xss = 64,

    /// <summary>SQL, code, path, command and SSRF patterns.</summary>
    Default = SqlInjection | CodeInjection | PathTraversal | CommandInjection | Ssrf,

    /// <summary>Every category, including template injection and XSS.</summary>
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
/// <remarks>
/// Each argument is checked as written and in each percent-decoded form of it (up to three layers),
/// so an encoded payload such as <c>%2e%2e%2f</c> or <c>%0a</c> is judged the way the tool that
/// decodes it will see it. SSRF targets are found by parsing hosts rather than by pattern (see
/// <see cref="ToolCallInjectionCategory.Ssrf"/>). Case-insensitive patterns match the same way under
/// every culture.
/// </remarks>
public sealed class ToolCallGuardrailRule : IGuardrailRule
{
    private readonly ToolCallGuardrailOptions _options;
    private readonly List<ArgumentCheck> _checks;

    /// <summary>Well-known property key for tool calls in GuardrailContext.Properties.</summary>
    public const string ToolCallsKey = "ToolCalls";

    /// <summary>Well-known property key for violations found.</summary>
    public const string ViolationsKey = "ToolCallViolations";

    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(200);

    // culture-invariant, so "i" and "I" are the same letter under every culture (tr-TR included)
    private const RegexOptions PatternOptions =
        RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant;

    // commands flagged right after a chaining operator, whatever follows them. The ones that are also
    // ordinary words or column names ("name; id; email", "dogs; cat people") are in WordCommands instead.
    private const string ChainedCommands =
        "whoami|uname|curl|wget|nc|ncat|netcat|bash|zsh|ksh|powershell|pwsh|printenv|nslookup|"
        + "telnet|tftp|xxd|socat|mkfifo|nohup|sudo|chmod|chown|useradd|crontab|certutil|bitsadmin|wmic|rundll32|"
        + "regsvr32|mshta|cscript|wscript|ifconfig|ipconfig|systeminfo|tasklist|taskkill";

    // commands flagged at the start of a line whatever follows them: none of them starts a sentence
    private const string LineStartCommands =
        "whoami|uname|wget|ncat|netcat|printenv|nslookup|telnet|tftp|xxd|socat|mkfifo|nohup|useradd|crontab|"
        + "certutil|bitsadmin|wmic|rundll32|regsvr32|mshta|cscript|wscript|ifconfig|ipconfig|systeminfo|tasklist|taskkill";

    // commands that double as words ("Cat videos", "Find attached"), flagged after an operator or at
    // the start of a line only when a command-shaped argument follows
    private const string WordCommands =
        "rm|cp|mv|echo|find|head|tail|env|touch|source|eval|exec|sed|awk|grep|python3?|perl|ruby|php|node|ssh|scp|"
        + "base64|dd|cat|ls|id|sh|nc|cmd|bash|zsh|curl|chmod|chown|sudo|powershell|pwsh";

    // commands that mean something with no argument at all, so one alone on a line is a command
    private const string BareCommands = "id|ls|env|sh|bash|zsh|cmd|powershell|pwsh";

    // everything a "$(...)" or a backtick pair has to start with to be a command substitution rather than
    // jQuery, a Makefile variable or inline code in prose
    private const string SubstitutedCommands =
        ChainedCommands + "|" + WordCommands + "|ping|sleep|nmap|tar|kill|ps|netstat|hostname|date|pwd|df|mount|docker|kubectl|git|apt|yum|pip3?|npm";

    // what follows a command rather than a word: an option, a path, a variable, a quoted argument or a URL
    private const string CommandArgument =
        @"(?=[ \t]+(?:-{1,2}[a-z]|[/\\~$]|\.{1,2}/|['""`]|[a-z]:\\|https?://))";

    // nothing follows: the command ends the line
    private const string EndsTheLine = @"(?=[ \t]*(?:[\r\n]|$))";

    // a command may be written with its path: "; /bin/rm -rf"
    private const string OptionalPath = @"(?:(?:/[\w.-]+)*/)?";

    /// <summary>Initializes a new instance of the <see cref="ToolCallGuardrailRule"/> class.</summary>
    /// <param name="options">Categories and allowlists. Defaults when null.</param>
    public ToolCallGuardrailRule(ToolCallGuardrailOptions? options = null)
    {
        _options = options ?? new();
        _checks = BuildChecks();

        // compiled patterns generate IL on first use; pay it here, not on the first request
        RegexPatterns.Warm(_checks.Where(c => c.Pattern is not null).Select(c => c.Pattern!));
        RegexPatterns.Warm(SsrfDetector.Patterns.Concat(PathTraversalDetector.Patterns).Append(SqlComments.Pattern));
    }

    /// <inheritdoc />
    public string Name => "tool-call-guardrail";
    /// <inheritdoc />
    public GuardrailPhase Phase => GuardrailPhase.Output;
    /// <inheritdoc />
    public int Order => 45;

    /// <inheritdoc />
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

                // one violation per argument is enough
                if (FindViolation(argValue) is { } found)
                    violations.Add(CreateViolation(call.ToolName, argName, found));
            }

            // RawContent is the serialized form of the same arguments, so it is only scanned when
            // nothing on this call was allow-listed; otherwise it would re-flag exactly the values
            // the allowlist excludes.
            var hasAllowedArguments = call.Arguments.Keys.Any(
                a => _options.AllowedArguments.Contains(a) || perToolAllowed?.Contains(a) == true);

            if (!hasAllowedArguments && call.RawContent is { Length: > 0 } rawContent
                && FindViolation(rawContent) is { } rawFound)
            {
                violations.Add(CreateViolation(call.ToolName, "_raw", rawFound));
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

    /// <summary>
    /// Runs the checks in order and returns the first one that fires - on the value, and when the
    /// value is a JSON object or array, on each string inside it.
    /// </summary>
    private (ToolCallInjectionCategory Category, string Description)? FindViolation(string value)
    {
        if (FindInText(value) is { } found)
            return found;

        foreach (var nested in JsonArgumentValues.Find(value))
        {
            if (FindInText(nested) is { } nestedFound)
                return nestedFound;
        }

        return null;
    }

    private (ToolCallInjectionCategory Category, string Description)? FindInText(string value)
    {
        var argument = new ArgumentText(value);

        foreach (var check in _checks)
        {
            if (check.Find(argument) is { } description)
                return (check.Category, description);
        }

        return null;
    }

    private static ToolCallViolation CreateViolation(
        string toolName, string argumentName, (ToolCallInjectionCategory Category, string Description) found) =>
        new()
        {
            ToolName = toolName,
            ArgumentName = argumentName,
            Category = found.Category,
            Description = found.Description
        };

    private List<ArgumentCheck> BuildChecks()
    {
        var checks = new List<ArgumentCheck>();
        var c = _options.Categories;

        if (c.HasFlag(ToolCallInjectionCategory.SqlInjection))
        {
            const ToolCallInjectionCategory sql = ToolCallInjectionCategory.SqlInjection;
            AddSqlPattern(checks, "SQL UNION injection", @"\bUNION\s+(?:(?:ALL|DISTINCT)\s+)?\(?\s*SELECT\b");
            AddSqlPattern(checks, "SQL DROP injection", @"\bDROP\s+(?:TABLE|DATABASE|INDEX|VIEW|SCHEMA)\b");
            // quoted: ' OR 'x'='x, ' OR 1=1, ' OR TRUE. The operand is bounded, which keeps the scan linear.
            AddSqlPattern(checks, "SQL tautology injection",
                @"'\s*OR\s+['""]?[^'""\r\n]{1,64}'?\s*=\s*['""]?|'\s*OR\s+TRUE\b");
            // equal operands without a quote in front: 1 OR 1=1, x OR 'a'='a (the query supplies the
            // closing quote). With AND the same comparison is the probe of a blind injection.
            AddSqlPattern(checks, "SQL tautology injection",
                @"\b(?:OR|AND)\s+(?:(?<n>\d{1,10})\s*=\s*\k<n>(?!\d)|(?<q>['""])(?<v>[^'""\r\n]{0,32})\k<q>\s*=\s*\k<q>\k<v>(?:\k<q>|(?![^\s)#;\-])))");
            // a value followed by an operand that is always true: 1 OR TRUE, ') OR NOT FALSE, 1 OR 1 --
            AddSqlPattern(checks, "SQL tautology injection",
                @"(?:\d|['"")])\s*\bOR\s+(?:TRUE\b|NOT\s+FALSE\b|\d{1,10}\s*(?:--|#|/\*))");
            // a comment that ends the statement right after a closing quote: admin'--, admin' #,
            // admin'/*. A comment marker on its own is left alone - "C#", or "-- " opening an email
            // signature, is not SQL. A "--" written straight onto the quote comments out whatever
            // follows it too: admin'-- and the rest.
            AddPattern(checks, sql, "SQL comment injection", @"['""][ \t]*(?:--|#|/\*)[ \t\r\-]*$|\w['""]--[ \t]", RegexOptions.Multiline);
            // a table name follows INTO and FROM; in a sentence it is "my", "the" or the like
            // ("delete from my calendar the 3pm meeting")
            AddSqlPattern(checks, "SQL INSERT/UPDATE injection",
                @"\b(?:INSERT\s+INTO|DELETE\s+FROM)\s+(?!(?:my|the|your|our|this|that|these|those|his|her|their|its|a|an|all|each|every)\b)[\w.\[\]""`]|\bUPDATE\s+\w+\s+SET\b");
            // EXEC or EXECUTE only with what can only be a call - the bare verb is ordinary English
            AddSqlPattern(checks, "SQL EXEC injection",
                @"\bEXEC(?:UTE)?\s*\(|\bEXEC(?:UTE)?\s+(?:@|(?:sp|xp)_\w|master\.|msdb\.)|\b(?:xp_cmdshell|sp_executesql|sp_oacreate|sp_configure)\b");
            // a second statement after a ';'. The keyword has to open a statement, not a clause of a
            // sentence ("I fixed the bug; update the ticket", "milk is out; select the organic one").
            AddSqlPattern(checks, "SQL batch terminator",
                @";\s*(?:SELECT\b(?=[^;\r\n]{0,200}\bFROM\b|\s+(?:\*|@@|\d|'|NULL\b|CASE\b|pg_sleep|sleep\s*\(|version\s*\(|current_user|user\s*\(|load_file))"
                + @"|DROP\s+(?:TABLE|DATABASE|INDEX|VIEW|SCHEMA|USER|ROLE|FUNCTION|PROCEDURE|TRIGGER)\b"
                + @"|INSERT\s+INTO\b|UPDATE\s+[\w.\[\]""`]+\s+SET\b|DELETE\s+FROM\b|TRUNCATE\s+TABLE\b"
                + @"|EXEC(?:UTE)?\s*(?:\(|@|'|(?:sp|xp)_|\w+\.)"
                + @"|UNION\s+(?:ALL\s+)?SELECT\b"
                + @"|ALTER\s+(?:TABLE|DATABASE|USER|ROLE|LOGIN|SYSTEM)\b"
                + @"|CREATE\s+(?:OR\s+REPLACE\s+)?(?:TABLE|DATABASE|USER|ROLE|LOGIN|FUNCTION|PROCEDURE|TRIGGER|VIEW|INDEX)\b"
                + @"|GRANT\s+\w+|SHUTDOWN\b|WAITFOR\s+DELAY\b)");
        }

        if (c.HasFlag(ToolCallInjectionCategory.CodeInjection))
        {
            const ToolCallInjectionCategory code = ToolCallInjectionCategory.CodeInjection;
            // "compile" is also an ordinary verb ("please compile (and send) the report"): a call has
            // no space before its parenthesis
            AddPattern(checks, code, "Python code injection",
                @"\b(?:eval|exec|__import__|os\.system|subprocess\.(?:call|run|Popen|check_output|check_call|getoutput)|importlib\.import_module)\s*\(|\bcompile\(");
            // the Function constructor, not the word: "the export function (added last week)"
            AddPattern(checks, code, "JavaScript code injection",
                @"\b(?:eval|setTimeout|setInterval)\s*\(|\bnew\s+Function\s*\(|(?-i:\bFunction)\s*\(|\brequire\s*\(\s*['""]child_process['""]\s*\)|\bchild_process\.(?:exec|execSync|spawn|spawnSync|execFile)\s*\(");
            AddPattern(checks, code, "Shell code injection via Python", @"\bos\.(?:system|popen|exec[lv]?[pe]?)\s*\(");
            AddPattern(checks, code, "Pickle deserialization", @"\b(?:pickle\.loads|yaml\.(?:load|unsafe_load)|marshal\.loads)\s*\(");
            AddPattern(checks, code, ".NET code injection", @"\b(?:Process\.Start|Assembly\.Load|Activator\.CreateInstance|Type\.InvokeMember)\s*\(");
        }

        if (c.HasFlag(ToolCallInjectionCategory.PathTraversal))
        {
            const ToolCallInjectionCategory path = ToolCallInjectionCategory.PathTraversal;
            checks.Add(new(path, a => PathTraversalDetector.HasTraversal(a) ? PathTraversalDetector.Traversal : null));
            checks.Add(new(path, a => PathTraversalDetector.HasEncodedTraversal(a) ? PathTraversalDetector.EncodedTraversal : null));
            checks.Add(new(path, a => PathTraversalDetector.HasSensitivePath(a) ? PathTraversalDetector.SensitiveFile : null));
            checks.Add(new(path, a => PathTraversalDetector.HasNulByte(a) ? PathTraversalDetector.NulByte : null));
        }

        if (c.HasFlag(ToolCallInjectionCategory.CommandInjection))
        {
            const ToolCallInjectionCategory command = ToolCallInjectionCategory.CommandInjection;
            AddPattern(checks, command, "Shell command chaining", @"[;&|]{1,2}\s*" + OptionalPath + "(?:" + ChainedCommands + @")\b");
            // a command that doubles as a word needs a command-shaped argument, or - after an operator - to
            // end the line; mid-list ("name; id; email") or alone on a line ("Python") it is a word
            AddPattern(checks, command, "Shell command chaining", @"(?:[;&|]{1,2}|[\r\n])[ \t]*" + OptionalPath + "(?:" + WordCommands + ")" + CommandArgument);
            AddPattern(checks, command, "Shell command chaining", @"[;&|]{1,2}[ \t]*" + OptionalPath + "(?:" + WordCommands + ")" + EndsTheLine);
            AddPattern(checks, command, "Shell command chaining", @"[\r\n][ \t]*" + OptionalPath + "(?:" + BareCommands + ")" + EndsTheLine);
            AddPattern(checks, command, "Shell command chaining", @"[\r\n][ \t]*" + OptionalPath + "(?:" + LineStartCommands + @")\b");
            // time- and network-based probes take a number or an option: ;sleep 10, |ping -n 5
            AddPattern(checks, command, "Shell command chaining", @"[;&|]{1,2}[ \t]*(?:sleep|ping|timeout)[ \t]+(?:-{1,2}[a-z]|\d)");
            // "$(...)" or backticks around a command. What they hold has to start with one: "$(document)"
            // is jQuery and "$(VERSION)" a Makefile variable. Backticks also mark inline code in prose
            // ("use `git status` to check"), so there the command needs a command-shaped argument or to
            // be one that is run bare. Bounded, so an unclosed "$(" or backtick cannot drive a quadratic scan.
            AddPattern(checks, command, "Command substitution",
                @"\$\(\s*" + OptionalPath + "(?:" + SubstitutedCommands + @")(?![\w-])[^)]{0,256}\)"
                + @"|`\s*" + OptionalPath + "(?:" + SubstitutedCommands + @")(?![\w-])[ \t]+(?:-{1,2}[a-z]|[/\\~$]|\.{1,2}/|['""]|https?://)[^`]{0,256}`"
                + @"|`\s*" + OptionalPath + "(?:" + ChainedCommands + "|" + BareCommands + @")\s*`");
            AddPattern(checks, command, "Pipe to shell", @"\|\s*" + OptionalPath + @"(?:bash|sh|zsh|ksh|cmd|powershell|pwsh)\b");
            // the ncat option search stops at the next "ncat ", so repeating the command can't multiply the scan
            AddPattern(checks, command, "Reverse shell patterns", @"bash\s+-i\s+>&|/dev/tcp/|\bnc\s+-[elp]|mkfifo|\bncat\s(?:[^\r\nn]|n(?!cat\s)){0,128}?-e");
        }

        if (c.HasFlag(ToolCallInjectionCategory.Ssrf))
        {
            checks.Add(new(ToolCallInjectionCategory.Ssrf, a => a.FirstFound(SsrfDetector.Find)));
        }

        if (c.HasFlag(ToolCallInjectionCategory.TemplateInjection))
        {
            const ToolCallInjectionCategory template = ToolCallInjectionCategory.TemplateInjection;
            // each expression is scanned only up to the next opener of its own kind ("{{", "${", "#{"),
            // so repeating the opener can't multiply the work; a nested opener is scanned from its own
            // start. The keyword search is atomic: only the first keyword in reach is tried
            AddPattern(checks, template, "Jinja2/Python template injection",
                @"\{\{(?>(?:[^\r\n{]|\{(?!\{)){0,256}?(?:config|self|request|lipsum|cycler|joiner|namespace|__class__|__mro__|__subclasses__))(?:[^\r\n{]|\{(?!\{)){0,256}?\}\}");
            AddPattern(checks, template, "Server-side template injection",
                @"\$\{(?>(?:[^\r\n$]|\$(?!\{)){0,256}?(?:Runtime|getClass|forName|exec|ProcessBuilder))(?:[^\r\n$]|\$(?!\{)){0,256}?\}");
            AddPattern(checks, template, "Handlebars injection", @"\{\{(?:#each|#if|#with|lookup|helper)\b");
            AddPattern(checks, template, "Expression language injection", @"#\{(?:[^\r\n#}]|#(?!\{)){0,256}\}");
        }

        if (c.HasFlag(ToolCallInjectionCategory.Xss))
        {
            const ToolCallInjectionCategory xss = ToolCallInjectionCategory.Xss;
            AddPattern(checks, xss, "Script tag XSS", @"<\s*script\b[^>]{0,1024}>");
            AddPattern(checks, xss, "Event handler XSS", @"\bon(?:error|load|click|mouseover|focus|blur|submit|change|input|keyup|keydown)\s*=");
            AddPattern(checks, xss, "JavaScript protocol XSS", @"javascript\s*:");
            AddPattern(checks, xss, "Data URI XSS", @"data\s*:\s*text/html");
            // attributes are scanned up to the next "<svg" rather than any "<", which an attribute value may hold
            AddPattern(checks, xss, "SVG XSS", @"<\s*svg\b(?:[^<>]|<(?!\s*svg\b)){0,1024}?\bon\w{1,32}\s*=");
        }

        return checks;
    }

    private static void AddPattern(
        List<ArgumentCheck> checks,
        ToolCallInjectionCategory category,
        string description,
        string pattern,
        RegexOptions extraOptions = RegexOptions.None)
    {
        var regex = new Regex(pattern, PatternOptions | extraOptions, RegexTimeout);
        checks.Add(new(category, a => a.AnyForm(regex.IsMatchOrFalse) ? description : null, regex));
    }

    // SQL reads a comment as white space, so "UNION/**/SELECT" is "UNION SELECT"; each pattern is
    // also tried on the text with its comments opened up
    private static void AddSqlPattern(List<ArgumentCheck> checks, string description, string pattern)
    {
        var regex = new Regex(pattern, PatternOptions, RegexTimeout);
        checks.Add(new(
            ToolCallInjectionCategory.SqlInjection,
            a => a.AnyForm(text => regex.IsMatchOrFalse(text)
                || (SqlComments.Strip(text) is { } uncommented && regex.IsMatchOrFalse(uncommented)))
                ? description
                : null,
            regex));
    }

    /// <summary>
    /// One detection: the category it reports, and a test that returns the violation description
    /// for an argument, or <c>null</c>.
    /// </summary>
    private sealed record ArgumentCheck(ToolCallInjectionCategory Category, Func<ArgumentText, string?> Find, Regex? Pattern = null);
}
