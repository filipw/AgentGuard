namespace AgentGuard.Pii.Recognizers.Germany;

/// <summary>
/// ISO 7064 Mod 11,10 check digit computation, used by German tax identification and VAT numbers.
/// </summary>
internal static class Iso7064Mod1110
{
    /// <summary>Computes the check digit over the leading <paramref name="digits"/> (excluding the check digit).</summary>
    public static int ComputeCheckDigit(ReadOnlySpan<char> digits)
    {
        var product = 10;
        foreach (var c in digits)
        {
            var total = (c - '0' + product) % 10;
            if (total == 0)
            {
                total = 10;
            }

            product = total * 2 % 11;
        }

        var check = 11 - product;
        return check == 10 ? 0 : check;
    }
}
