using System.Text.Json;
using System.Text.Json.Nodes;
using AgentGuard.Pii.Analyzer;
using AgentGuard.Pii.Analyzer.Context;
using AgentGuard.Pii.Anonymizer.Operators;
using AgentGuard.Pii.Structured;
using FluentAssertions;
using Xunit;

namespace AgentGuard.Pii.Tests;

public class StructuredEngineTests
{
    private const string Card = "4012888888881881"; // Luhn-valid Visa test number
    private readonly StructuredEngine _engine = new();

    [Fact]
    public void ShouldRedactStringValues_AndPreserveNonStringTypes()
    {
        const string json = """
            {
              "user": { "name": "Acme", "email": "john@example.com", "age": 42, "active": true },
              "cards": ["4012888888881881"],
              "note": "nothing to see"
            }
            """;

        var redacted = _engine.AnonymizeJson(json);
        var node = JsonNode.Parse(redacted)!;

        node["user"]!["email"]!.GetValue<string>().Should().Be("<EMAIL_ADDRESS>");
        node["cards"]![0]!.GetValue<string>().Should().Be("<CREDIT_CARD>");
        // non-string values and benign strings are untouched
        node["user"]!["age"]!.GetValue<int>().Should().Be(42);
        node["user"]!["active"]!.GetValue<bool>().Should().BeTrue();
        node["note"]!.GetValue<string>().Should().Be("nothing to see");
    }

    [Fact]
    public void ShouldRedactOnlyIncludedPaths()
    {
        const string json = """{ "user": { "email": "john@example.com", "backup": "jane@example.com" } }""";

        var scope = new JsonRedactionScope { IncludePaths = ["user.email"] };
        var node = JsonNode.Parse(_engine.AnonymizeJson(json, scope))!;

        node["user"]!["email"]!.GetValue<string>().Should().Be("<EMAIL_ADDRESS>");
        node["user"]!["backup"]!.GetValue<string>().Should().Be("jane@example.com");
    }

    [Fact]
    public void ShouldSkipExcludedPaths()
    {
        const string json = """{ "primary": "john@example.com", "secondary": "jane@example.com" }""";

        var scope = new JsonRedactionScope { ExcludePaths = ["secondary"] };
        var node = JsonNode.Parse(_engine.AnonymizeJson(json, scope))!;

        node["primary"]!.GetValue<string>().Should().Be("<EMAIL_ADDRESS>");
        node["secondary"]!.GetValue<string>().Should().Be("jane@example.com");
    }

    [Fact]
    public void ShouldApplyPerEntityOperator_InJson()
    {
        const string json = """{ "email": "john@example.com" }""";
        var operators = new Dictionary<string, OperatorConfig>
        {
            ["EMAIL_ADDRESS"] = new("hash", new Dictionary<string, object> { [OperatorParams.Salt] = "0123456789abcdef" }),
        };

        var node = JsonNode.Parse(_engine.AnonymizeJson(json, operators: operators))!;

        node["email"]!.GetValue<string>().Should().HaveLength(64); // sha256 hex
    }

    [Fact]
    public void ShouldHandleNestedArraysOfObjects()
    {
        const string json = """
            { "contacts": [ { "email": "a@x.com" }, { "email": "b@y.com" } ] }
            """;

        var node = JsonNode.Parse(_engine.AnonymizeJson(json))!;
        var contacts = node["contacts"]!.AsArray();

        contacts[0]!["email"]!.GetValue<string>().Should().Be("<EMAIL_ADDRESS>");
        contacts[1]!["email"]!.GetValue<string>().Should().Be("<EMAIL_ADDRESS>");
    }

    [Fact]
    public void ShouldRedactPiiColumns_AndLeaveBenignColumnsUntouched()
    {
        var header = new[] { "email", "card", "city" };
        var rows = new List<IReadOnlyList<string>>
        {
            new[] { "a@x.com", Card, "Boston" },
            new[] { "b@y.com", Card, "Paris" },
            new[] { "c@z.com", Card, "Berlin" },
        };

        var result = _engine.AnonymizeCsv(header, rows);

        result.Rows.Should().AllSatisfy(r =>
        {
            r[0].Should().Be("<EMAIL_ADDRESS>");
            r[1].Should().Be("<CREDIT_CARD>");
        });
        // benign city column is preserved
        result.Rows.Select(r => r[2]).Should().Equal("Boston", "Paris", "Berlin");
        result.ColumnEntities.Should().ContainKeys("email", "card");
        result.ColumnEntities.Should().NotContainKey("city");
    }

    [Fact]
    public void ShouldPreserveRowShape_InCsv()
    {
        var header = new[] { "email", "city" };
        var rows = new List<IReadOnlyList<string>> { new[] { "a@x.com", "Boston" } };

        var result = _engine.AnonymizeCsv(header, rows);

        result.Header.Should().Equal("email", "city");
        result.Rows.Should().ContainSingle().Which.Should().HaveCount(2);
    }

    [Fact]
    public void ShouldHonorExcludeColumns()
    {
        var header = new[] { "email" };
        var rows = new List<IReadOnlyList<string>> { new[] { "a@x.com" } };

        var result = _engine.AnonymizeCsv(header, rows, new StructuredCsvOptions { ExcludeColumns = ["email"] });

        result.Rows[0][0].Should().Be("a@x.com");
        result.ColumnEntities.Should().BeEmpty();
    }

    [Fact]
    public void ShouldApplyPerEntityOperator_InCsv()
    {
        var header = new[] { "email" };
        var rows = new List<IReadOnlyList<string>>
        {
            new[] { "a@x.com" },
            new[] { "b@y.com" },
        };
        var options = new StructuredCsvOptions
        {
            Operators = new Dictionary<string, OperatorConfig>
            {
                ["EMAIL_ADDRESS"] = new("hash", new Dictionary<string, object> { [OperatorParams.Salt] = "0123456789abcdef" }),
            },
        };

        var result = _engine.AnonymizeCsv(header, rows, options);

        result.Rows.Should().AllSatisfy(r => r[0].Should().HaveLength(64));
    }

    [Fact]
    public void ShouldWorkWithCountryPacks_InCsv()
    {
        // a custom analyzer with the india pack detects Aadhaar (Verhoeff-valid, scores MaxScore)
        var analyzer = new AnalyzerEngine(
            PiiRecognizers.CreateRegistry("en", ["in"]),
            new LemmaContextAwareEnhancer());
        var engine = new StructuredEngine(analyzer);

        var header = new[] { "aadhaar" };
        var rows = new List<IReadOnlyList<string>>
        {
            new[] { "234123412346" },
            new[] { "234123412346" },
        };

        var result = engine.AnonymizeCsv(header, rows);

        result.Rows.Should().AllSatisfy(r => r[0].Should().Be("<IN_AADHAAR>"));
        result.ColumnEntities["aadhaar"].Should().Be("IN_AADHAAR");
    }
}
