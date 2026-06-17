using AgentGuard.Pii.Analyzer;
using FluentAssertions;
using Xunit;

namespace AgentGuard.Onnx.Tests;

/// <summary>
/// CI-safe tests for <see cref="GlinerNerRecognizer"/> and <see cref="GlinerNerOptions"/> that do not
/// require a real ONNX model (option defaults, ctor validation, supported-entity derivation, the
/// label map, and requested-entity subset filtering via a stubbed session-free recognizer).
/// </summary>
public class GlinerNerRecognizerTests
{
    private static readonly string[] UnsupportedEntities = ["CREDIT_CARD", "US_SSN"];


    [Fact]
    public void ShouldExposeDefaultEntityLabelMap()
    {
        GlinerNerOptions.DefaultEntityLabelMap.Should().Contain("person", "PERSON");
        GlinerNerOptions.DefaultEntityLabelMap.Should().Contain("location", "LOCATION");
        GlinerNerOptions.DefaultEntityLabelMap.Should().Contain("organization", "ORGANIZATION");
        GlinerNerOptions.DefaultEntityLabelMap.Should().Contain("date", "DATE_TIME");
    }

    [Fact]
    public void ShouldDefaultThresholdToZeroPointFive()
    {
        var options = new GlinerNerOptions { ModelPath = "m", TokenizerPath = "t", ConfigPath = "c" };
        options.NerThreshold.Should().Be(0.5f);
        options.MaxSpanWidth.Should().Be(12);
    }

    [Fact]
    public void ShouldThrow_WhenModelPathDoesNotExist()
    {
        var act = () => new GlinerNerRecognizer(new GlinerNerOptions
        {
            ModelPath = "/nonexistent/model.onnx",
            TokenizerPath = "/nonexistent/spm.model",
            ConfigPath = "/nonexistent/config.json",
        });

        act.Should().Throw<FileNotFoundException>().WithMessage("*model.onnx*");
    }

    [Fact]
    public void ShouldThrow_WhenThresholdIsAboveOne()
    {
        var modelTemp = Path.GetTempFileName();
        var tokenizerTemp = Path.GetTempFileName();
        var configTemp = Path.GetTempFileName();
        try
        {
            var act = () => new GlinerNerRecognizer(new GlinerNerOptions
            {
                ModelPath = modelTemp,
                TokenizerPath = tokenizerTemp,
                ConfigPath = configTemp,
                NerThreshold = 1.1f,
            });

            act.Should().Throw<ArgumentOutOfRangeException>().WithMessage("*NerThreshold*");
        }
        finally
        {
            File.Delete(modelTemp);
            File.Delete(tokenizerTemp);
            File.Delete(configTemp);
        }
    }

    [Fact]
    public void ShouldDeriveSupportedEntitiesFromLabelMap()
    {
        var options = new GlinerNerOptions { ModelPath = "m", TokenizerPath = "t", ConfigPath = "c" };
        var recognizer = new GlinerNerRecognizer(session: null!, options);

        recognizer.SupportedEntities.Should().BeEquivalentTo("PERSON", "LOCATION", "ORGANIZATION", "DATE_TIME");
        recognizer.CountryCode.Should().BeNull();
        recognizer.Context.Should().BeNull("the model carries its own confidence, no surface-form boost");
    }

    [Fact]
    public void ShouldHonorCustomEntityLabelMap()
    {
        var options = new GlinerNerOptions
        {
            ModelPath = "m",
            TokenizerPath = "t",
            ConfigPath = "c",
            EntityLabelMap = new Dictionary<string, string> { ["full name"] = "PERSON", ["city"] = "LOCATION" },
        };
        var recognizer = new GlinerNerRecognizer(session: null!, options);

        recognizer.SupportedEntities.Should().BeEquivalentTo("PERSON", "LOCATION");
    }

    [Fact]
    public void ShouldReturnEmpty_WhenTextIsWhitespace()
    {
        var options = new GlinerNerOptions { ModelPath = "m", TokenizerPath = "t", ConfigPath = "c" };
        var recognizer = new GlinerNerRecognizer(session: null!, options);

        // whitespace short-circuits before the session is touched (session is null here)
        recognizer.Analyze("   ", recognizer.SupportedEntities).Should().BeEmpty();
    }

    [Fact]
    public void ShouldReturnEmpty_WhenNoRequestedEntityIsSupported()
    {
        var options = new GlinerNerOptions { ModelPath = "m", TokenizerPath = "t", ConfigPath = "c" };
        var recognizer = new GlinerNerRecognizer(session: null!, options);

        // none of the requested entities map to a model label -> no labels to prompt, session untouched
        recognizer.Analyze("Some text here", UnsupportedEntities).Should().BeEmpty();
    }
}
