using AgentGuard.Pii.Analyzer;
using AgentGuard.Pii.Anonymizer;
using AgentGuard.Pii.Anonymizer.Operators;
using FluentAssertions;
using Xunit;

namespace AgentGuard.Pii.Tests;

public class DeanonymizerTests
{
    private const string Key = "1111111111111111"; // 128-bit
    private readonly AnonymizerEngine _anonymizer = new();
    private readonly DeanonymizerEngine _deanonymizer = new();

    private static Dictionary<string, OperatorConfig> EncryptWith(string key) => new()
    {
        ["DEFAULT"] = new("encrypt", new Dictionary<string, object> { [OperatorParams.Key] = key }),
    };

    private static Dictionary<string, OperatorConfig> DecryptWith(string key) => new()
    {
        ["DEFAULT"] = new("decrypt", new Dictionary<string, object> { [OperatorParams.Key] = key }),
    };

    [Fact]
    public void ShouldRestoreOriginal_WhenEncryptThenDecrypt()
    {
        const string text = "Contact John at john@example.com please";
        var results = new List<RecognizerResult>
        {
            new("PERSON", 8, 12, 0.9),
            new("EMAIL_ADDRESS", 16, 32, 1.0),
        };

        var anonymized = _anonymizer.Anonymize(text, results, EncryptWith(Key));
        anonymized.Text.Should().NotContain("John").And.NotContain("john@example.com");

        var restored = _deanonymizer.Deanonymize(anonymized.Text, anonymized.Items, DecryptWith(Key));

        restored.Text.Should().Be(text);
    }

    [Fact]
    public void ShouldRestoreOriginal_WhenMultipleAdjacentSpans()
    {
        // two adjacent same-type spans merge into one during anonymize; the round-trip still restores
        const string text = "James Bond drinks martinis";
        var results = new List<RecognizerResult>
        {
            new("PERSON", 0, 5, 0.9),  // James
            new("PERSON", 6, 10, 0.9), // Bond
        };

        var anonymized = _anonymizer.Anonymize(text, results, EncryptWith(Key));
        var restored = _deanonymizer.Deanonymize(anonymized.Text, anonymized.Items, DecryptWith(Key));

        restored.Text.Should().Be(text);
    }

    [Fact]
    public void ShouldRestoreOriginal_ViaDeidentificationResult()
    {
        const string text = "SSN 078-05-1120 belongs to Alice";
        var results = new List<RecognizerResult>
        {
            new("US_SSN", 4, 15, 0.85),
            new("PERSON", 27, 32, 0.9),
        };

        var anonymized = _anonymizer.Anonymize(text, results, EncryptWith(Key));
        var deid = PiiDeidentificationResult.FromEngineResult(anonymized);

        deid.IsReversible.Should().BeTrue();

        var restored = _deanonymizer.Deanonymize(deid.AnonymizedText, deid.Items, DecryptWith(Key));
        restored.Text.Should().Be(text);
    }

    [Fact]
    public void ShouldFailClearly_WhenKeyIsWrong()
    {
        const string text = "Contact john@example.com";
        var results = new List<RecognizerResult> { new("EMAIL_ADDRESS", 8, 24, 1.0) };
        var anonymized = _anonymizer.Anonymize(text, results, EncryptWith(Key));

        var act = () => _deanonymizer.Deanonymize(anonymized.Text, anonymized.Items, DecryptWith("2222222222222222"));

        act.Should().Throw<InvalidOperationException>().WithMessage("*key is incorrect*");
    }

    [Fact]
    public void ShouldFailClearly_WhenCiphertextTruncated()
    {
        // a corrupted/truncated span that is still valid base64url but decodes to < 16 bytes (no IV)
        var items = new List<OperatorResult> { new(0, 4, "EMAIL_ADDRESS", "AAAA", "encrypt") };

        var act = () => _deanonymizer.Deanonymize("AAAA", items, DecryptWith(Key));

        act.Should().Throw<InvalidOperationException>().WithMessage("*not a valid*ciphertext*");
    }

    [Fact]
    public void ShouldFailClearly_WhenKeyMissing()
    {
        const string text = "Contact john@example.com";
        var results = new List<RecognizerResult> { new("EMAIL_ADDRESS", 8, 24, 1.0) };
        var anonymized = _anonymizer.Anonymize(text, results, EncryptWith(Key));

        var operators = new Dictionary<string, OperatorConfig> { ["DEFAULT"] = new("decrypt") };
        var act = () => _deanonymizer.Deanonymize(anonymized.Text, anonymized.Items, operators);

        act.Should().Throw<ArgumentException>().WithMessage("*key*");
    }

    [Fact]
    public void ShouldReportNotReversible_WhenAnonymizedWithReplace()
    {
        const string text = "Contact john@example.com";
        var results = new List<RecognizerResult> { new("EMAIL_ADDRESS", 8, 24, 1.0) };
        var anonymized = _anonymizer.Anonymize(text, results); // replace operator

        PiiDeidentificationResult.FromEngineResult(anonymized).IsReversible.Should().BeFalse();

        var act = () => _deanonymizer.Deanonymize(anonymized.Text, anonymized.Items, DecryptWith(Key));

        act.Should().Throw<InvalidOperationException>().WithMessage("*non-reversible*");
    }

    [Theory]
    [InlineData("replace")]
    [InlineData("mask")]
    [InlineData("hash")]
    public void ShouldReportLossyOperatorsAsNotReversible(string lossyOperator)
    {
        DeanonymizerEngine.IsReversible(lossyOperator).Should().BeFalse();
    }

    [Fact]
    public void ShouldReportEncryptAndCustomAsReversible()
    {
        DeanonymizerEngine.IsReversible("encrypt").Should().BeTrue();
        DeanonymizerEngine.IsReversible("custom").Should().BeTrue();
    }

    [Fact]
    public void ShouldApplyCustomReverseOperator()
    {
        // anonymize with a custom transform (rot-ish placeholder), then reverse with a custom inverse
        const string text = "id ABCDEF here";
        var results = new List<RecognizerResult> { new("CUSTOM_ID", 3, 9, 1.0) };

        var anonymizeOps = new Dictionary<string, OperatorConfig>
        {
            ["DEFAULT"] = new("custom", new Dictionary<string, object>
            {
                [CustomOperator.Lambda] = (Func<string, string>)(s => new string(s.Reverse().ToArray())),
            }),
        };

        var anonymized = _anonymizer.Anonymize(text, results, anonymizeOps);
        anonymized.Text.Should().Be("id FEDCBA here");

        var reverseOps = new Dictionary<string, OperatorConfig>
        {
            ["DEFAULT"] = new("custom", new Dictionary<string, object>
            {
                [CustomOperator.Lambda] = (Func<string, string>)(s => new string(s.Reverse().ToArray())),
            }),
        };

        var restored = _deanonymizer.Deanonymize(anonymized.Text, anonymized.Items, reverseOps);
        restored.Text.Should().Be(text);
    }

    [Fact]
    public void ShouldExposeDecryptAndCustomDeanonymizers()
    {
        _deanonymizer.GetDeanonymizers().Should().Contain("decrypt").And.Contain("custom");
    }
}
