using AgentGuard.Pii.Analyzer;
using AgentGuard.Pii.Recognizers.Generic;
using AgentGuard.Pii.Recognizers.Us;
using FluentAssertions;
using Xunit;

namespace AgentGuard.Pii.Tests;

public class RecognizerTests
{
    private static readonly IReadOnlyList<string> AllEntities = [];

    [Theory]
    [InlineData("4095-2609-9393-4932")] // valid Luhn
    [InlineData("4095 2609 9393 4932")]
    [InlineData("4012888888881881")]
    public void ShouldDetectAndValidate_WhenCreditCardIsValid(string card)
    {
        var recognizer = new CreditCardRecognizer();
        var results = recognizer.Analyze(card, AllEntities);

        results.Should().ContainSingle();
        results[0].EntityType.Should().Be("CREDIT_CARD");
        results[0].Score.Should().Be(EntityRecognizer.MaxScore);
    }

    [Fact]
    public void ShouldDropResult_WhenCreditCardFailsLuhn()
    {
        var recognizer = new CreditCardRecognizer();
        // matches the regex shape but fails the checksum
        var results = recognizer.Analyze("4095-2609-9393-4933", AllEntities);

        results.Should().BeEmpty();
    }

    [Fact]
    public void ShouldDetectEmail_WhenValid()
    {
        var recognizer = new EmailRecognizer();
        var results = recognizer.Analyze("contact me at john.doe@example.com please", AllEntities);

        results.Should().ContainSingle();
        results[0].Score.Should().Be(EntityRecognizer.MaxScore);
    }

    [Fact]
    public void ShouldDetectValidIban_AndDropInvalidChecksum()
    {
        var recognizer = new IbanRecognizer();

        recognizer.Analyze("DE89370400440532013000", AllEntities).Should().ContainSingle();
        recognizer.Analyze("DE89370400440532013001", AllEntities).Should().BeEmpty();
    }

    [Fact]
    public void ShouldDetectBitcoinAddress_AndDropInvalidChecksum()
    {
        var recognizer = new CryptoRecognizer();

        // valid P2PKH genesis address
        recognizer.Analyze("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", AllEntities).Should().ContainSingle();
        // corrupted checksum
        recognizer.Analyze("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb", AllEntities).Should().BeEmpty();
    }

    [Theory]
    [InlineData("192.168.1.1", true)]
    [InlineData("256.1.1.1", false)] // regex won't match an out-of-range octet
    public void ShouldDetectIpv4_WhenValid(string text, bool expected)
    {
        var recognizer = new IpRecognizer();
        var results = recognizer.Analyze(text, AllEntities);

        results.Any().Should().Be(expected);
    }

    [Fact]
    public void ShouldDetectMacAddress()
    {
        var recognizer = new MacAddressRecognizer();
        recognizer.Analyze("00:1A:2B:3C:4D:5E", AllEntities).Should().ContainSingle();
        recognizer.Analyze("FF:FF:FF:FF:FF:FF", AllEntities).Should().BeEmpty(); // broadcast invalidated
    }

    [Fact]
    public void ShouldInvalidate_WhenSsnIsImpossible()
    {
        var recognizer = new UsSsnRecognizer();

        // all zeros group and blacklisted samples are dropped
        recognizer.Analyze("000-12-0000", AllEntities).Should().BeEmpty();
        recognizer.Analyze("078-05-1120", AllEntities).Should().BeEmpty(); // blacklisted sample
        recognizer.Analyze("111-11-1111", AllEntities).Should().BeEmpty(); // all same digit
    }

    [Fact]
    public void ShouldDetectSsn_WhenMediumPatternValid()
    {
        var recognizer = new UsSsnRecognizer();
        var results = recognizer.Analyze("234-56-7890", AllEntities);

        results.Should().ContainSingle();
        results[0].EntityType.Should().Be("US_SSN");
    }

    [Fact]
    public void ShouldDetectPhoneNumber_WhenUsFormatted()
    {
        var recognizer = new PhoneRecognizer();
        var results = recognizer.Analyze("call me at (212) 555-0182", AllEntities);

        results.Should().NotBeEmpty();
        results[0].EntityType.Should().Be("PHONE_NUMBER");
    }

    [Fact]
    public void ShouldDetectItin()
    {
        var recognizer = new UsItinRecognizer();
        var results = recognizer.Analyze("900-70-1234", AllEntities);

        results.Should().NotBeEmpty();
        results[0].EntityType.Should().Be("US_ITIN");
    }
}
