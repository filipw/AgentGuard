using AgentGuard.Pii.Analyzer;
using PhoneNumbers;

namespace AgentGuard.Pii.Recognizers.Generic;

/// <summary>
/// Recognizes multi-regional phone numbers using libphonenumber.
/// </summary>
public sealed class PhoneRecognizer : EntityRecognizer
{
    private const double Score = 0.4;

    private static readonly IReadOnlyList<string> DefaultContext =
        ["phone", "number", "telephone", "cell", "cellphone", "mobile", "call"];

    // default regions: US, UK, DE, FR, IL, IN, CA, BR. "UK" maps to the ISO region "GB".
    private static readonly IReadOnlyList<string> DefaultRegions = ["US", "GB", "DE", "FR", "IL", "IN", "CA", "BR"];

    private readonly IReadOnlyList<string> _supportedRegions;
    private readonly PhoneNumberUtil.Leniency _leniency;
    private readonly PhoneNumberUtil _phoneUtil = PhoneNumberUtil.GetInstance();

    /// <summary>Initializes a new instance of the <see cref="PhoneRecognizer"/> class.</summary>
    public PhoneRecognizer(
        string supportedEntity = "PHONE_NUMBER",
        string supportedLanguage = "en",
        IReadOnlyList<string>? supportedRegions = null,
        PhoneNumberUtil.Leniency leniency = PhoneNumberUtil.Leniency.VALID)
        : base([supportedEntity], supportedLanguage: supportedLanguage, context: DefaultContext)
    {
        _supportedRegions = supportedRegions ?? DefaultRegions;
        _leniency = leniency;
    }

    /// <inheritdoc />
    public override IReadOnlyList<RecognizerResult> Analyze(string text, IReadOnlyList<string> entities)
    {
        var results = new List<RecognizerResult>();
        foreach (var region in _supportedRegions)
        {
            foreach (var match in _phoneUtil.FindNumbers(text, region, _leniency, long.MaxValue))
            {
                results.Add(new RecognizerResult(
                    entityType: SupportedEntities[0],
                    start: match.Start,
                    end: match.Start + match.RawString.Length,
                    score: Score,
                    recognitionMetadata: new Dictionary<string, object>
                    {
                        [RecognizerResult.RecognizerNameKey] = Name,
                        [RecognizerResult.RecognizerIdentifierKey] = Id,
                    },
                    analysisExplanation: new AnalysisExplanation(
                        recognizer: nameof(PhoneRecognizer),
                        originalScore: Score,
                        textualExplanation: $"Recognized as {region} region phone number, using PhoneRecognizer")));
            }
        }

        return RemoveDuplicates(results);
    }
}
