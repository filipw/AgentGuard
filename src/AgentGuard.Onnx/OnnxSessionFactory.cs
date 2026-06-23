using Microsoft.ML.OnnxRuntime;

namespace AgentGuard.Onnx;

/// <summary>
/// Builds <see cref="InferenceSession"/> instances with consistent options across all AgentGuard models.
/// </summary>
internal static class OnnxSessionFactory
{
    /// <summary>
    /// Creates an inference session for <paramref name="modelPath"/> with graph-optimization chatter
    /// suppressed. ONNX Runtime logs a warning ("could not find a CPU kernel and hence can't constant
    /// fold ...") for every fp16 MatMul/Gemm it cannot fold on CPU during session init; the warnings are
    /// harmless but flood stderr, so logging is capped at error level.
    /// </summary>
    public static InferenceSession Create(string modelPath)
    {
        // ensure the env is disposed deterministically at process exit (avoids a native shutdown race).
        OnnxRuntimeShutdown.EnsureHookRegistered();

        using var options = new SessionOptions { LogSeverityLevel = OrtLoggingLevel.ORT_LOGGING_LEVEL_ERROR };
        return new InferenceSession(modelPath, options);
    }
}
