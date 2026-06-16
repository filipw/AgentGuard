namespace AgentGuard.Pii.Anonymizer.Operators;

/// <summary>
/// Masks part of a PII span with a fixed character, from the start or the end.
/// </summary>
public sealed class MaskOperator : IOperator
{
    /// <inheritdoc />
    public string Name => "mask";

    /// <inheritdoc />
    public OperatorType Type => OperatorType.Anonymize;

    /// <inheritdoc />
    public string Operate(string text, IReadOnlyDictionary<string, object> parameters)
    {
        var maskingChar = OperatorParams.Get<string>(parameters, OperatorParams.MaskingChar, "*")!;
        var charsToMask = GetCharsToMask(parameters);
        var fromEnd = OperatorParams.Get<bool>(parameters, OperatorParams.FromEnd);

        var effective = Math.Min(text.Length, charsToMask > 0 ? charsToMask : 0);
        var mask = string.Concat(Enumerable.Repeat(maskingChar, effective));

        if (!fromEnd)
        {
            return mask + text[effective..];
        }

        var fromIndex = text.Length - effective;
        return text[..fromIndex] + mask;
    }

    /// <inheritdoc />
    public void Validate(IReadOnlyDictionary<string, object> parameters)
    {
        var maskingChar = OperatorParams.Get<string>(parameters, OperatorParams.MaskingChar);
        if (maskingChar is null)
        {
            throw new ArgumentException($"Invalid parameter: '{OperatorParams.MaskingChar}' is required.");
        }

        if (maskingChar.Length != 1)
        {
            throw new ArgumentException($"Invalid input, '{OperatorParams.MaskingChar}' must be a single character.");
        }

        if (!parameters.ContainsKey(OperatorParams.CharsToMask) || parameters[OperatorParams.CharsToMask] is not int)
        {
            throw new ArgumentException($"Invalid parameter: '{OperatorParams.CharsToMask}' must be an integer.");
        }

        if (!parameters.ContainsKey(OperatorParams.FromEnd) || parameters[OperatorParams.FromEnd] is not bool)
        {
            throw new ArgumentException($"Invalid parameter: '{OperatorParams.FromEnd}' must be a boolean.");
        }
    }

    private static int GetCharsToMask(IReadOnlyDictionary<string, object> parameters) =>
        parameters.TryGetValue(OperatorParams.CharsToMask, out var value) && value is int i ? i : 0;
}
