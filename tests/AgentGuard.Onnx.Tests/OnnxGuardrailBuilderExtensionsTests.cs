using AgentGuard.Core.Builders;
using FluentAssertions;
using TasmanianDevil.Onnx;
using Xunit;

namespace AgentGuard.Onnx.Tests;

public class OnnxGuardrailBuilderExtensionsTests
{
    [Theory]
    [InlineData(float.NaN)]
    [InlineData(1.5f)]
    [InlineData(-0.5f)]
    public void ShouldThrow_WhenNerThresholdIsNotANumberBetweenZeroAndOne(float threshold)
    {
        // a NaN threshold would emit no span at all; checked before any model file is opened
        var act = () => new GuardrailPolicyBuilder().RedactPiiWithNer(new GlinerNerOptions
        {
            ModelPath = "/nonexistent/model.onnx",
            TokenizerPath = "/nonexistent/spm.model",
            ConfigPath = "/nonexistent/config.json",
            NerThreshold = threshold
        });

        act.Should().Throw<ArgumentOutOfRangeException>().WithMessage("*NerThreshold*");
    }
}
