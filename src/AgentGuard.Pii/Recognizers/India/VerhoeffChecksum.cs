namespace AgentGuard.Pii.Recognizers.India;

/// <summary>
/// Verhoeff checksum validation (used by the Indian Aadhaar number), based on the dihedral group D5.
/// </summary>
internal static class VerhoeffChecksum
{
    private static readonly int[][] D =
    [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
        [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
        [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
        [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
        [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
        [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
        [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
        [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
        [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
    ];

    private static readonly int[][] P =
    [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
        [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
        [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
        [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
        [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
        [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
        [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
    ];

    private static readonly int[] Inv = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9];

    /// <summary>Returns <c>true</c> if <paramref name="digits"/> (check digit included) is Verhoeff-valid.</summary>
    public static bool IsValid(ReadOnlySpan<char> digits)
    {
        var c = 0;
        var len = digits.Length;
        for (var i = 0; i < len; i++)
        {
            // iterate the number from its least-significant digit
            var digit = digits[len - 1 - i] - '0';
            c = D[c][P[i % 8][digit]];
        }

        return Inv[c] == 0;
    }
}
