using AgentGuard.Pii.Analyzer;
using AgentGuard.Pii.Recognizers.Germany;
using AgentGuard.Pii.Recognizers.India;
using AgentGuard.Pii.Recognizers.Italy;
using AgentGuard.Pii.Recognizers.Spain;
using AgentGuard.Pii.Recognizers.Uk;
using AgentGuard.Pii.Recognizers.Us;
using FluentAssertions;
using Xunit;

namespace AgentGuard.Pii.Tests;

public class CountryRecognizerTests
{
    private static readonly IReadOnlyList<string> All = [];

    // --- US ---

    [Fact]
    public void ShouldValidateAbaRouting_WhenChecksumValid()
    {
        var r = new AbaRoutingRecognizer();
        r.Analyze("122105155", All).Should().ContainSingle().Which.Score.Should().Be(EntityRecognizer.MaxScore);
        r.Analyze("122105156", All).Should().BeEmpty();
    }

    [Fact]
    public void ShouldValidateNpi_WhenLuhnValid()
    {
        var r = new UsNpiRecognizer();
        r.Analyze("1234567893", All).Should().ContainSingle().Which.Score.Should().Be(EntityRecognizer.MaxScore);
        r.Analyze("1234567890", All).Should().BeEmpty();
        r.Analyze("1111111111", All).Should().BeEmpty(); // degenerate body invalidated
    }

    [Fact]
    public void ShouldValidateMedicalLicense_WhenDeaChecksumValid()
    {
        var r = new MedicalLicenseRecognizer();
        r.Analyze("AB1234563", All).Should().ContainSingle().Which.Score.Should().Be(EntityRecognizer.MaxScore);
        r.Analyze("AB1234560", All).Should().BeEmpty();
    }

    // --- UK ---

    [Fact]
    public void ShouldValidateNhs_WhenMod11Valid()
    {
        var r = new UkNhsRecognizer();
        r.Analyze("943 476 5919", All).Should().ContainSingle().Which.Score.Should().Be(EntityRecognizer.MaxScore);
        r.Analyze("943 476 5918", All).Should().BeEmpty();
    }

    [Fact]
    public void ShouldRejectDrivingLicence_WhenSurnameAllNines()
    {
        var r = new UkDrivingLicenceRecognizer();
        r.Analyze("MORGA657054AB9CD", All).Should().ContainSingle();
        r.Analyze("99999657054AB9CD", All).Should().BeEmpty();
    }

    [Fact]
    public void ShouldValidateVehicleRegistration_WhenCurrentAgeInRange()
    {
        var r = new UkVehicleRegistrationRecognizer();
        r.Analyze("AB51ABC", All).Should().Contain(x => x.Score == EntityRecognizer.MaxScore);
    }

    // --- Germany ---

    [Fact]
    public void ShouldValidateTaxId_WhenMod1110Valid()
    {
        var r = new DeTaxIdRecognizer();
        r.Analyze("86095742719", All).Should().ContainSingle().Which.Score.Should().Be(EntityRecognizer.MaxScore);
        r.Analyze("86095742711", All).Should().BeEmpty();
    }

    [Fact]
    public void ShouldValidateSocialSecurity_WhenCheckDigitValid()
    {
        var r = new DeSocialSecurityRecognizer();
        r.Analyze("15070649C103", All).Should().ContainSingle().Which.Score.Should().Be(EntityRecognizer.MaxScore);
        r.Analyze("15070649C104", All).Should().BeEmpty();
    }

    [Fact]
    public void ShouldValidateIdCard_WhenCheckDigitValid()
    {
        var r = new DeIdCardRecognizer();
        r.Analyze("L01X00T44", All).Should().ContainSingle().Which.Score.Should().Be(EntityRecognizer.MaxScore);
        r.Analyze("L01X00T45", All).Should().BeEmpty();
    }

    [Fact]
    public void ShouldKeepLegacyIdCard_WhenTFormat()
    {
        // legacy "T + 8 digits" predates the check digit and keeps its base score
        var r = new DeIdCardRecognizer();
        var results = r.Analyze("T22000124", All);
        results.Should().ContainSingle();
        results[0].Score.Should().BeLessThan(EntityRecognizer.MaxScore);
    }

    [Fact]
    public void ShouldValidatePassport_WhenCheckDigitValid()
    {
        var r = new DePassportRecognizer();
        r.Analyze("C01X00T41", All).Should().ContainSingle().Which.Score.Should().Be(EntityRecognizer.MaxScore);
        r.Analyze("C01X00T42", All).Should().BeEmpty();
    }

    [Fact]
    public void ShouldValidateVatId_WhenChecksumValidOrStrict()
    {
        new DeVatIdRecognizer().Analyze("DE123456788", All).Should().ContainSingle().Which.Score.Should().Be(EntityRecognizer.MaxScore);

        // default mode keeps a checksum-failing match at its base score; strict mode drops it
        new DeVatIdRecognizer().Analyze("DE123456789", All).Should().ContainSingle().Which.Score.Should().BeLessThan(EntityRecognizer.MaxScore);
        new DeVatIdRecognizer(strictChecksum: true).Analyze("DE123456789", All).Should().BeEmpty();
    }

    // --- India ---

    [Fact]
    public void ShouldValidateAadhaar_WhenVerhoeffValid()
    {
        var r = new InAadhaarRecognizer();
        r.Analyze("234123412346", All).Should().ContainSingle().Which.Score.Should().Be(EntityRecognizer.MaxScore);
        r.Analyze("234123412347", All).Should().BeEmpty();
        r.Analyze("200000000002", All).Should().BeEmpty(); // palindrome rejected
    }

    [Fact]
    public void ShouldValidateGstin_WhenStructureValid()
    {
        var r = new InGstinRecognizer();
        r.Analyze("27AAPFU0939F1ZV", All).Should().ContainSingle().Which.Score.Should().Be(EntityRecognizer.MaxScore);
        r.Analyze("99AAPFU0939F1ZV", All).Should().BeEmpty(); // state code out of range
    }

    // --- Italy ---

    [Fact]
    public void ShouldPromoteFiscalCode_WhenControlCharMatches()
    {
        var r = new ItFiscalCodeRecognizer();
        r.Analyze("MRTMTT25D09F205Z", All).Should().ContainSingle().Which.Score.Should().Be(EntityRecognizer.MaxScore);
        // a wrong control char keeps the base score rather than dropping the match
        r.Analyze("MRTMTT25D09F205A", All).Should().ContainSingle().Which.Score.Should().BeLessThan(EntityRecognizer.MaxScore);
    }

    [Fact]
    public void ShouldValidateVatCode_WhenChecksumValid()
    {
        var r = new ItVatCodeRecognizer();
        r.Analyze("07643520567", All).Should().ContainSingle().Which.Score.Should().Be(EntityRecognizer.MaxScore);
        r.Analyze("07643520568", All).Should().BeEmpty();
    }

    // --- Spain ---

    [Fact]
    public void ShouldValidateNif_WhenControlLetterValid()
    {
        var r = new EsNifRecognizer();
        r.Analyze("12345678Z", All).Should().ContainSingle().Which.Score.Should().Be(EntityRecognizer.MaxScore);
        r.Analyze("12345678A", All).Should().BeEmpty();
    }

    [Fact]
    public void ShouldValidateNie_WhenControlLetterValid()
    {
        var r = new EsNieRecognizer();
        r.Analyze("X1234567L", All).Should().ContainSingle().Which.Score.Should().Be(EntityRecognizer.MaxScore);
        r.Analyze("X1234567A", All).Should().BeEmpty();
    }
}
