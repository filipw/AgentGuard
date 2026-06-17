using AgentGuard.Pii.Analyzer;

namespace AgentGuard.Pii.Recognizers.India;

/// <summary>
/// Recognizes Indian vehicle registration numbers across the historical and current formats using
/// regex, with validation against the state / RTO-district code map and diplomatic / foreign-mission
/// rules. Validation can only promote a match (it never drops one).
/// </summary>
public sealed class InVehicleRegistrationRecognizer : PatternRecognizer
{
    private static readonly IReadOnlyList<Pattern> DefaultPatterns =
    [
        new Pattern("India Vehicle Registration (Very Weak)", @"\b[A-Z]{1}(?!0000)[0-9]{4}\b", 0.01),
        new Pattern("India Vehicle Registration (Very Weak)", @"\b[A-Z]{2}(?!0000)\d{4}\b", 0.01),
        new Pattern("India Vehicle Registration (Very Weak)", @"\b(I)(?!00000)\d{5}\b", 0.01),
        new Pattern("India Vehicle Registration (Weak)", @"\b[A-Z]{3}(?!0000)\d{4}\b", 0.20),
        new Pattern("India Vehicle Registration (Medium)", @"\b\d{1,3}(CD|CC|UN)[1-9]{1}[0-9]{1,3}\b", 0.40),
        new Pattern("India Vehicle Registration", @"\b[A-Z]{2}\d{1}[A-Z]{1,3}(?!0000)\d{4}\b", 0.50),
        new Pattern("India Vehicle Registration", @"\b[A-Z]{2}\d{2}[A-Z]{1,2}(?!0000)\d{4}\b", 0.50),
        new Pattern("India Vehicle Registration", @"\b[2-9]{1}[1-9]{1}(BH)(?!0000)\d{4}[A-HJ-NP-Z]{2}\b", 0.85),
        new Pattern("India Vehicle Registration", @"\b(?!00)\d{2}(A|B|C|D|E|F|H|K|P|R|X)\d{6}[A-Z]{1}\b", 0.85),
    ];

    private static readonly IReadOnlyList<string> DefaultContext = ["RTO", "vehicle", "plate", "registration"];

    private static readonly IReadOnlyList<(string, string)> ReplacementPairs = [("-", ""), (" ", ""), (":", "")];

    private static readonly HashSet<int> ForeignMissionCodes =
    [
        84, 85, 89, 93, 94, 95, 97, 98, 99, 102, 104, 105, 106, 109, 111, 112, 113, 117, 119, 120,
        121, 122, 123, 125, 126, 128, 133, 134, 135, 137, 141, 145, 147, 149, 152, 153, 155, 156,
        157, 159, 160,
    ];

    private static readonly string[] DiplomaticCodes = ["CC", "CD", "UN"];

    private static readonly HashSet<string> TwoFactorRegistrationPrefix =
    [
        // union territories
        "AN", "CH", "DH", "DL", "JK", "LA", "LD", "PY",
        // states
        "AP", "AR", "AS", "BR", "CG", "GA", "GJ", "HR", "HP", "JH", "KA", "KL", "MP", "MH", "MN",
        "ML", "MZ", "NL", "OD", "PB", "RJ", "SK", "TN", "TS", "TR", "UP", "UK", "WB", "UT",
        // old states
        "UL", "OR", "UA",
        // old union territories
        "CT", "DN",
        // non-standard
        "DD",
    ];

    private static readonly Dictionary<string, HashSet<string>> StateRtoDistrictMap = BuildDistrictMap();

    /// <summary>Initializes a new instance of the <see cref="InVehicleRegistrationRecognizer"/> class.</summary>
    public InVehicleRegistrationRecognizer(string supportedEntity = "IN_VEHICLE_REGISTRATION", string supportedLanguage = "en")
        : base(supportedEntity, patterns: DefaultPatterns, context: DefaultContext, supportedLanguage: supportedLanguage, countryCode: "in")
    {
    }

    /// <inheritdoc />
    public override bool? ValidateResult(string patternText)
    {
        var value = SanitizeValue(patternText, ReplacementPairs);
        if (value.Length < 8)
        {
            return null;
        }

        var firstTwo = value[..2].ToUpperInvariant();
        if (!TwoFactorRegistrationPrefix.Contains(firstTwo))
        {
            return null;
        }

        if (char.IsDigit(value[2]))
        {
            var distCode = char.IsDigit(value[3]) ? value[2..4] : value[2..3];
            var registrationDigits = value[^4..];
            if (registrationDigits.All(char.IsDigit))
            {
                var reg = int.Parse(registrationDigits, System.Globalization.CultureInfo.InvariantCulture);
                if (reg is > 0 and <= 9999 &&
                    StateRtoDistrictMap.TryGetValue(firstTwo, out var districts) &&
                    districts.Contains(distCode))
                {
                    return true;
                }
            }
        }

        foreach (var diplomatic in DiplomaticCodes)
        {
            var idx = value.IndexOf(diplomatic, StringComparison.Ordinal);
            if (idx < 0)
            {
                continue;
            }

            var prefix = value[..idx];
            if (prefix.Length > 0 && prefix.All(char.IsDigit))
            {
                var p = int.Parse(prefix, System.Globalization.CultureInfo.InvariantCulture);
                if ((p is >= 1 and <= 80) || ForeignMissionCodes.Contains(p))
                {
                    return true;
                }
            }
        }

        return null;
    }

    // two-digit zero-padded codes from..to inclusive, minus the excluded values
    private static IEnumerable<string> Pad2(int from, int to, params int[] except)
    {
        var skip = new HashSet<int>(except);
        for (var i = from; i <= to; i++)
        {
            if (!skip.Contains(i))
            {
                yield return i.ToString("D2", System.Globalization.CultureInfo.InvariantCulture);
            }
        }
    }

    // unpadded codes from..to inclusive
    private static IEnumerable<string> Plain(int from, int to)
    {
        for (var i = from; i <= to; i++)
        {
            yield return i.ToString(System.Globalization.CultureInfo.InvariantCulture);
        }
    }

    private static Dictionary<string, HashSet<string>> BuildDistrictMap() => new()
    {
        ["AN"] = ["01"],
        ["AP"] = ["39", "40"],
        ["AR"] = [.. Pad2(1, 22, 18, 21)],
        ["AS"] = [.. Pad2(1, 34, 21)],
        ["BR"] = [.. Pad2(1, 11), "19", "21", "22", .. Pad2(24, 34), "37", "38", "39", "43", "44", "45", "46", "50", "51", "52", "53", "55", "56"],
        ["CG"] = [.. Pad2(1, 30)],
        ["CH"] = [.. Pad2(1, 4)],
        ["DD"] = [.. Pad2(1, 3)],
        ["DN"] = ["09"],
        ["DL"] = [.. Plain(1, 13)],
        ["GA"] = [.. Pad2(1, 12)],
        ["GJ"] = [.. Plain(1, 39)],
        ["HP"] = [.. Pad2(1, 99, 21)],
        ["HR"] = [.. Pad2(1, 99, 21)],
        ["JH"] = [.. Pad2(1, 24, 21)],
        ["JK"] = [.. Pad2(1, 22, 21)],
        ["KA"] = [.. Pad2(1, 71, 21)],
        ["KL"] = [.. Pad2(1, 99, 21)],
        ["LA"] = ["01", "02"],
        ["LD"] = [.. Pad2(1, 9)],
        ["MH"] = [.. Pad2(1, 51, 21)],
        ["ML"] = [.. Pad2(1, 10)],
        ["MN"] = [.. Pad2(1, 7)],
        ["MP"] = [.. Pad2(1, 71, 21)],
        ["MZ"] = [.. Pad2(1, 8)],
        ["NL"] = [.. Pad2(1, 10)],
        ["OD"] = [.. Pad2(1, 35, 21)],
        ["OR"] = [.. Pad2(1, 31, 21)],
        ["PB"] = [.. Pad2(1, 99, 21)],
        ["PY"] = [.. Pad2(1, 5)],
        ["RJ"] = [.. Pad2(1, 58, 21)],
        ["SK"] = [.. Pad2(1, 8)],
        ["TN"] = [.. Pad2(1, 99, 21)],
        ["TR"] = [.. Pad2(1, 8)],
        ["TS"] = [.. Pad2(1, 38, 21)],
        ["UK"] = [.. Pad2(1, 20)],
        ["UP"] = [.. Pad2(11, 96)],
        ["WB"] = [.. Pad2(1, 98, 21)],
    };
}
