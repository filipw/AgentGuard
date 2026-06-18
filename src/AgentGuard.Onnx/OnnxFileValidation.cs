namespace AgentGuard.Onnx;

/// <summary>
/// Shared path validation for the BYO-download ONNX rules (model, tokenizer, config/prefix files).
/// </summary>
internal static class OnnxFileValidation
{
    /// <summary>
    /// Validates that <paramref name="path"/> is non-empty and points to an existing file, returning
    /// its absolute path. Throws <see cref="ArgumentException"/> when empty and
    /// <see cref="FileNotFoundException"/> when the file is missing.
    /// </summary>
    /// <param name="path">The configured file path.</param>
    /// <param name="paramName">The owning option name, for the exception message.</param>
    /// <param name="description">Human-readable description of the file, for the exception message.</param>
    internal static string RequireFile(string? path, string paramName, string description)
    {
        if (string.IsNullOrWhiteSpace(path))
            throw new ArgumentException($"{description} path is required.", paramName);

        var full = Path.GetFullPath(path);
        if (!File.Exists(full))
            throw new FileNotFoundException($"{description} not found at '{full}'.", full);

        return full;
    }
}
