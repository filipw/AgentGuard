namespace AgentGuard.Onnx;

/// <summary>
/// Range checks shared by the ONNX classifier rules. They run when a rule is constructed, before any
/// model file is opened, so that a misconfigured option fails fast instead of quietly changing what
/// the rule blocks.
/// </summary>
internal static class OptionValidation
{
    /// <summary>
    /// Throws unless <paramref name="value"/> lies between 0.0 and 1.0. NaN is rejected: every
    /// comparison with NaN is false, so a NaN threshold would never block anything.
    /// </summary>
    /// <param name="value">The configured value.</param>
    /// <param name="optionName">The option's name, for the exception message.</param>
    /// <param name="paramName">The caller's options parameter name, for the exception.</param>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when the value is NaN or outside 0.0-1.0.</exception>
    public static void RequireProbability(float value, string optionName, string paramName)
    {
        if (value is not (>= 0f and <= 1f))
            throw new ArgumentOutOfRangeException(paramName, value, $"{optionName} must be between 0.0 and 1.0.");
    }

    /// <summary>
    /// Throws unless <paramref name="maxTokenLength"/> leaves room for at least one input token next to
    /// the <paramref name="specialTokenCount"/> tokens the classifier's session adds to every input.
    /// </summary>
    /// <param name="maxTokenLength">The configured maximum sequence length.</param>
    /// <param name="specialTokenCount">Tokens the session adds around the input.</param>
    /// <param name="paramName">The caller's options parameter name, for the exception.</param>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when no input token would fit.</exception>
    public static void RequireMaxTokenLength(int maxTokenLength, int specialTokenCount, string paramName)
    {
        if (maxTokenLength <= specialTokenCount)
        {
            throw new ArgumentOutOfRangeException(
                paramName, maxTokenLength, $"MaxTokenLength must be greater than {specialTokenCount} to leave room for any input tokens.");
        }
    }
}
