using AgentGuard.Core.Telemetry;
using OpenTelemetry.Metrics;
using OpenTelemetry.Trace;

namespace AgentGuard.Hosting;

/// <summary>
/// Convenience extension methods for registering AgentGuard telemetry with OpenTelemetry.
/// </summary>
public static class OpenTelemetryExtensions
{
    /// <summary>
    /// Adds the AgentGuard <see cref="System.Diagnostics.ActivitySource"/> to the tracer provider,
    /// enabling collection of guardrail pipeline and rule evaluation spans.
    /// </summary>
    /// <param name="builder">The <see cref="TracerProviderBuilder"/> to configure.</param>
    /// <returns>The configured <see cref="TracerProviderBuilder"/> for chaining.</returns>
    public static TracerProviderBuilder AddAgentGuardInstrumentation(this TracerProviderBuilder builder) =>
        builder.AddSource(AgentGuardTelemetry.SourceName);

    /// <summary>
    /// Adds the AgentGuard <see cref="System.Diagnostics.Metrics.Meter"/> to the meter provider,
    /// enabling collection of guardrail evaluation metrics (counters, histograms).
    /// </summary>
    /// <param name="builder">The <see cref="MeterProviderBuilder"/> to configure.</param>
    /// <returns>The configured <see cref="MeterProviderBuilder"/> for chaining.</returns>
    public static MeterProviderBuilder AddAgentGuardInstrumentation(this MeterProviderBuilder builder) =>
        builder.AddMeter(AgentGuardTelemetry.SourceName);
}
