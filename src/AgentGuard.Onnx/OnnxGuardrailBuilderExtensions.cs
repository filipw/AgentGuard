using AgentGuard.Core.Builders;

namespace AgentGuard.Onnx;

/// <summary>
/// Extension methods for adding ONNX-based guardrail rules to the policy builder.
/// </summary>
public static class OnnxGuardrailBuilderExtensions
{
    /// <summary>
    /// Adds ONNX-based prompt injection detection (order 12) using a pre-downloaded DeBERTa v3 model.
    /// Runs between regex-based detection (order 10) and LLM-based detection (order 15).
    /// </summary>
    /// <param name="builder">The policy builder.</param>
    /// <param name="options">ONNX model options including model and tokenizer file paths.</param>
    /// <returns>The builder for chaining.</returns>
    public static GuardrailPolicyBuilder BlockPromptInjectionWithOnnx(
        this GuardrailPolicyBuilder builder,
        OnnxPromptInjectionOptions options)
    {
        builder.AddRule(new OnnxPromptInjectionRule(options));
        return builder;
    }

    /// <summary>
    /// Adds ONNX-based prompt injection detection (order 12) using a pre-downloaded DeBERTa v3 model.
    /// </summary>
    /// <param name="builder">The policy builder.</param>
    /// <param name="modelPath">Path to the ONNX model file.</param>
    /// <param name="tokenizerPath">Path to the HuggingFace tokenizer.json file.</param>
    /// <param name="threshold">Confidence threshold (0.0–1.0). Default: 0.5.</param>
    /// <returns>The builder for chaining.</returns>
    public static GuardrailPolicyBuilder BlockPromptInjectionWithOnnx(
        this GuardrailPolicyBuilder builder,
        string modelPath,
        string tokenizerPath,
        float threshold = 0.5f)
    {
        return builder.BlockPromptInjectionWithOnnx(new OnnxPromptInjectionOptions
        {
            ModelPath = modelPath,
            TokenizerPath = tokenizerPath,
            Threshold = threshold
        });
    }
}
