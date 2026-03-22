using AgentGuard.Core.Builders;

namespace AgentGuard.Onnx;

/// <summary>
/// Extension methods for adding ONNX-based guardrail rules to the policy builder.
/// </summary>
public static class OnnxGuardrailBuilderExtensions
{
    /// <summary>
    /// Adds ONNX-based prompt injection detection using the bundled StackOne Defender model (order 11).
    /// This is the recommended ONNX classifier — fast (~8 ms), accurate (F1 ~0.97), and requires no separate download.
    /// Runs before DeBERTa (order 12) and LLM-based detection (order 15).
    /// </summary>
    /// <param name="builder">The policy builder.</param>
    /// <param name="options">Optional configuration. If null, default options with bundled model are used.</param>
    /// <returns>The builder for chaining.</returns>
    public static GuardrailPolicyBuilder BlockPromptInjectionWithOnnx(
        this GuardrailPolicyBuilder builder,
        DefenderPromptInjectionOptions? options = null)
    {
        builder.AddRule(new DefenderPromptInjectionRule(options));
        return builder;
    }

    /// <summary>
    /// Adds ONNX-based prompt injection detection using the bundled StackOne Defender model (order 11).
    /// </summary>
    /// <param name="builder">The policy builder.</param>
    /// <param name="threshold">Confidence threshold (0.0–1.0). Default: 0.5.</param>
    /// <returns>The builder for chaining.</returns>
    public static GuardrailPolicyBuilder BlockPromptInjectionWithOnnx(
        this GuardrailPolicyBuilder builder,
        float threshold)
    {
        return builder.BlockPromptInjectionWithOnnx(new DefenderPromptInjectionOptions { Threshold = threshold });
    }

    /// <summary>
    /// Adds ONNX-based prompt injection detection (order 12) using the DeBERTa v3 model.
    /// The ONNX model must be downloaded separately — see <c>eng/download-onnx-model.sh</c>.
    /// For most use cases, prefer <see cref="BlockPromptInjectionWithOnnx(GuardrailPolicyBuilder, DefenderPromptInjectionOptions?)"/>
    /// which uses the bundled StackOne Defender model (faster, higher accuracy, no download required).
    /// </summary>
    /// <param name="builder">The policy builder.</param>
    /// <param name="options">ONNX model options including model and tokenizer file paths.</param>
    /// <returns>The builder for chaining.</returns>
    public static GuardrailPolicyBuilder BlockPromptInjectionWithDeberta(
        this GuardrailPolicyBuilder builder,
        OnnxPromptInjectionOptions options)
    {
        builder.AddRule(new OnnxPromptInjectionRule(options));
        return builder;
    }

    /// <summary>
    /// Adds ONNX-based prompt injection detection (order 12) using the DeBERTa v3 model.
    /// The ONNX model must be downloaded separately — see <c>eng/download-onnx-model.sh</c>.
    /// </summary>
    /// <param name="builder">The policy builder.</param>
    /// <param name="modelPath">Path to the ONNX model file.</param>
    /// <param name="tokenizerPath">Path to the SentencePiece model file.</param>
    /// <param name="threshold">Confidence threshold (0.0–1.0). Default: 0.5.</param>
    /// <returns>The builder for chaining.</returns>
    public static GuardrailPolicyBuilder BlockPromptInjectionWithDeberta(
        this GuardrailPolicyBuilder builder,
        string modelPath,
        string tokenizerPath,
        float threshold = 0.5f)
    {
        return builder.BlockPromptInjectionWithDeberta(new OnnxPromptInjectionOptions
        {
            ModelPath = modelPath,
            TokenizerPath = tokenizerPath,
            Threshold = threshold
        });
    }
}
