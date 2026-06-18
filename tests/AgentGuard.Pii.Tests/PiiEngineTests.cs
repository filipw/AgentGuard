using System.Text.Json.Nodes;
using AgentGuard.Pii;
using AgentGuard.Pii.Anonymizer.Operators;
using FluentAssertions;
using Xunit;

namespace AgentGuard.Pii.Tests;

public class PiiEngineTests
{
    private const string Card = "4012888888881881";
    private const string Key = "0123456789abcdef"; // 128-bit

    [Fact]
    public void ShouldAnonymizeFreeText_WithDefaultReplace()
    {
        var engine = new PiiEngine();

        engine.Anonymize("email john@example.com").Text.Should().Be("email <EMAIL_ADDRESS>");
    }

    [Fact]
    public void ShouldReturnDetections_FromAnalyze()
    {
        var engine = new PiiEngine();

        engine.Analyze("email john@example.com").Should().Contain(r => r.EntityType == "EMAIL_ADDRESS");
    }

    [Fact]
    public void ShouldRoundTrip_DeidentifyThenReidentify()
    {
        var engine = new PiiEngine(new PiiOptions
        {
            Operators = new Dictionary<string, OperatorConfig>
            {
                ["DEFAULT"] = new("encrypt", new Dictionary<string, object> { [OperatorParams.Key] = Key }),
            },
        });

        const string text = "Contact mary@clinic.org about file 078-05-1120.";
        var deid = engine.Deidentify(text);
        deid.IsReversible.Should().BeTrue();
        deid.AnonymizedText.Should().NotContain("mary@clinic.org");

        var reverseOps = new Dictionary<string, OperatorConfig>
        {
            ["DEFAULT"] = new("decrypt", new Dictionary<string, object> { [OperatorParams.Key] = Key }),
        };
        engine.Reidentify(deid, reverseOps).Text.Should().Be(text);
    }

    [Fact]
    public void ShouldRedactJson_RespectingScope()
    {
        var engine = new PiiEngine();
        const string json = """{ "email": "john@example.com", "note": "hi" }""";

        var node = JsonNode.Parse(engine.AnonymizeJson(json))!;

        node["email"]!.GetValue<string>().Should().Be("<EMAIL_ADDRESS>");
        node["note"]!.GetValue<string>().Should().Be("hi");
    }

    [Fact]
    public void ShouldRedactCsvColumns()
    {
        var engine = new PiiEngine();
        var header = new[] { "email", "city" };
        string[][] rawRows = [["a@x.com", "Berlin"], ["b@y.com", "Oslo"]];
        var rows = rawRows.Select(r => (IReadOnlyList<string>)r).ToList();

        var result = engine.AnonymizeCsv(header, rows);

        result.Rows.Should().AllSatisfy(r => r[0].Should().Be("<EMAIL_ADDRESS>"));
        result.Rows.Select(r => r[1]).Should().Equal("Berlin", "Oslo");
    }

    [Fact]
    public void ShouldAnonymizeBatchList_InOrder()
    {
        var engine = new PiiEngine();

        var results = engine.AnonymizeBatch(["email a@x.com", "no pii"]);

        results.Should().HaveCount(2);
        results[0].Text.Should().Be("email <EMAIL_ADDRESS>");
        results[1].Text.Should().Be("no pii");
    }

    [Fact]
    public void ShouldAnonymizeBatchDictionary_PreservingKeys()
    {
        var engine = new PiiEngine();
        var records = new Dictionary<string, string> { ["primary"] = "a@x.com", ["note"] = "ok" };

        var results = engine.AnonymizeBatch(records);

        results["primary"].Text.Should().Be("<EMAIL_ADDRESS>");
        results["note"].Text.Should().Be("ok");
    }

    [Fact]
    public void ShouldHonorCountryPacks_ViaCreate()
    {
        var engine = PiiEngine.Create("en", "in");

        // Aadhaar (Verhoeff-valid) is only detected when the india pack is enabled
        engine.Anonymize("234123412346").Text.Should().Be("<IN_AADHAAR>");
    }

    [Fact]
    public void ShouldHandleEmptyText()
    {
        var engine = new PiiEngine();

        engine.Anonymize("").Text.Should().Be("");
        engine.Analyze("").Should().BeEmpty();
    }
}
