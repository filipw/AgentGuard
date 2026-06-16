using AgentGuard.Pii.Analyzer;
using AgentGuard.Pii.Anonymizer;
using AgentGuard.Pii.Anonymizer.Operators;
using FluentAssertions;
using Xunit;

namespace AgentGuard.Pii.Tests;

public class AnonymizerTests
{
    private readonly AnonymizerEngine _engine = new();

    [Fact]
    public void ShouldReplaceWithEntityTag_WhenNoOperatorGiven()
    {
        var results = new List<RecognizerResult>
        {
            new("PERSON", 11, 15, 0.8),
            new("PERSON", 17, 27, 0.8),
        };

        var result = _engine.Anonymize("My name is Bond, James Bond", results);

        result.Text.Should().Be("My name is <PERSON>, <PERSON>");
        result.Items.Should().HaveCount(2);
    }

    [Fact]
    public void ShouldApplyReplaceOperator_WithCustomValue()
    {
        var results = new List<RecognizerResult> { new("EMAIL_ADDRESS", 0, 16, 1.0) };
        var operators = new Dictionary<string, OperatorConfig>
        {
            ["DEFAULT"] = new("replace", new Dictionary<string, object> { [OperatorParams.NewValue] = "[REDACTED]" }),
        };

        var result = _engine.Anonymize("john@example.com is mine", results, operators);

        result.Text.Should().Be("[REDACTED] is mine");
    }

    [Fact]
    public void ShouldMaskFromEnd()
    {
        var results = new List<RecognizerResult> { new("CREDIT_CARD", 0, 16, 1.0) };
        var operators = new Dictionary<string, OperatorConfig>
        {
            ["DEFAULT"] = new("mask", new Dictionary<string, object>
            {
                [OperatorParams.MaskingChar] = "*",
                [OperatorParams.CharsToMask] = 12,
                [OperatorParams.FromEnd] = false,
            }),
        };

        var result = _engine.Anonymize("4012888888881881", results, operators);

        result.Text.Should().Be("************1881");
    }

    [Fact]
    public void ShouldRedactToEmpty()
    {
        var results = new List<RecognizerResult> { new("PHONE_NUMBER", 8, 14, 1.0) };
        var operators = new Dictionary<string, OperatorConfig> { ["DEFAULT"] = new("redact") };

        var result = _engine.Anonymize("call me 123456 now", results, operators);

        result.Text.Should().Be("call me  now");
    }

    [Fact]
    public void ShouldHashDeterministically_WhenSaltProvided()
    {
        var results = new List<RecognizerResult> { new("EMAIL_ADDRESS", 0, 16, 1.0) };
        var operators = new Dictionary<string, OperatorConfig>
        {
            ["DEFAULT"] = new("hash", new Dictionary<string, object> { [OperatorParams.Salt] = "0123456789abcdef" }),
        };

        var first = _engine.Anonymize("john@example.com", results, operators).Text;
        var second = _engine.Anonymize("john@example.com", results, operators).Text;

        first.Should().Be(second);
        first.Should().HaveLength(64); // sha256 hex
    }

    [Fact]
    public void ShouldEncryptAndDecrypt_RoundTrip()
    {
        const string key = "1111111111111111"; // 128-bit
        var encrypted = AesCipher.Encrypt(System.Text.Encoding.UTF8.GetBytes(key), "secret value");

        AesCipher.Decrypt(System.Text.Encoding.UTF8.GetBytes(key), encrypted).Should().Be("secret value");
    }

    [Fact]
    public void ShouldResolveOverlap_KeepingHigherScore()
    {
        // two entities of the same type overlapping should be merged
        var results = new List<RecognizerResult>
        {
            new("PERSON", 0, 4, 0.6),
            new("PERSON", 2, 8, 0.9),
        };

        var result = _engine.Anonymize("abcdefgh", results);

        result.Items.Should().ContainSingle();
        result.Text.Should().Be("<PERSON>");
    }

    [Fact]
    public void ShouldMergeAdjacentSameTypeEntities_SeparatedBySpace()
    {
        var results = new List<RecognizerResult>
        {
            new("PERSON", 0, 5, 0.85),
            new("PERSON", 6, 11, 0.85),
        };

        var result = _engine.Anonymize("James Smith", results);

        result.Items.Should().ContainSingle();
        result.Text.Should().Be("<PERSON>");
    }
}
