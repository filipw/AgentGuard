using FluentAssertions;
using Xunit;

namespace AgentGuard.Onnx.Tests;

/// <summary>
/// Gated tests for the process-wide pooling and the real inference path of
/// <see cref="GlinerModelSession"/>. These require the GLiNER model files (same env vars as the e2e
/// suite) and are skipped otherwise. They confirm two recognizers on the same files share one ONNX
/// session and that the session predicts a known span end to end.
/// </summary>
public class GlinerModelSessionPoolingTests
{
    [GlinerModelFact]
    public void ShouldShareOneSession_WhenAcquiredTwiceWithSameKey()
    {
        var (model, tokenizer, config) = Paths();

        var a = GlinerModelSession.Acquire(model, tokenizer, config, maxTokenLength: 384, maxSpanWidth: 12, maxChunkChars: 1200);
        try
        {
            var countAfterFirst = GlinerModelSession.ActiveSessionCount;
            var b = GlinerModelSession.Acquire(model, tokenizer, config, maxTokenLength: 384, maxSpanWidth: 12, maxChunkChars: 1200);
            try
            {
                b.Should().BeSameAs(a, "the same key must return the pooled session");
                GlinerModelSession.ActiveSessionCount.Should().Be(countAfterFirst, "a second acquire reuses the cached session");
            }
            finally
            {
                b.Dispose();
            }
        }
        finally
        {
            a.Dispose();
        }
    }

    [GlinerModelFact]
    public void ShouldPredictKnownSpan()
    {
        var (model, tokenizer, config) = Paths();
        var session = GlinerModelSession.Acquire(model, tokenizer, config, maxTokenLength: 384, maxSpanWidth: 12, maxChunkChars: 1200);
        try
        {
            const string text = "Contact Jane Doe in Berlin today.";
            var spans = session.Predict(text, ["person", "location"], threshold: 0.5f);

            var person = spans.First(s => s.Label == "person");
            text[person.CharStart..person.CharEnd].Should().Be("Jane Doe");
            person.Score.Should().BeGreaterThan(0.5f);

            var location = spans.First(s => s.Label == "location");
            text[location.CharStart..location.CharEnd].Should().Be("Berlin");
        }
        finally
        {
            session.Dispose();
        }
    }

    private static (string Model, string Tokenizer, string Config) Paths() =>
    (
        Environment.GetEnvironmentVariable("AGENTGUARD_GLINER_ONNX_MODEL_PATH")!,
        Environment.GetEnvironmentVariable("AGENTGUARD_GLINER_TOKENIZER_PATH")!,
        Environment.GetEnvironmentVariable("AGENTGUARD_GLINER_CONFIG_PATH")!
    );
}

/// <summary>Skip fact attribute that checks for GLiNER model availability via environment variables.</summary>
[AttributeUsage(AttributeTargets.Method)]
public sealed class GlinerModelFactAttribute : Xunit.FactAttribute
{
    public GlinerModelFactAttribute()
    {
        var modelPath = Environment.GetEnvironmentVariable("AGENTGUARD_GLINER_ONNX_MODEL_PATH");
        var tokenizerPath = Environment.GetEnvironmentVariable("AGENTGUARD_GLINER_TOKENIZER_PATH");
        var configPath = Environment.GetEnvironmentVariable("AGENTGUARD_GLINER_CONFIG_PATH");

        if (string.IsNullOrEmpty(modelPath) || string.IsNullOrEmpty(tokenizerPath) || string.IsNullOrEmpty(configPath))
            Skip = "Set AGENTGUARD_GLINER_ONNX_MODEL_PATH, AGENTGUARD_GLINER_TOKENIZER_PATH, and AGENTGUARD_GLINER_CONFIG_PATH to run GLiNER session tests.";
    }
}
