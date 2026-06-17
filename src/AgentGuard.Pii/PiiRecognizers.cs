using AgentGuard.Pii.Analyzer;
using AgentGuard.Pii.Recognizers.Generic;
using AgentGuard.Pii.Recognizers.Germany;
using AgentGuard.Pii.Recognizers.India;
using AgentGuard.Pii.Recognizers.Italy;
using AgentGuard.Pii.Recognizers.Spain;
using AgentGuard.Pii.Recognizers.Uk;
using AgentGuard.Pii.Recognizers.Us;

namespace AgentGuard.Pii;

/// <summary>Factory for the built-in recognizers: a generic set plus opt-in country-specific packs.</summary>
public static class PiiRecognizers
{
    /// <summary>
    /// Creates the default recognizers: the generic set plus the complete US pack. Country packs other
    /// than US are opt-in via <see cref="CreateRegistry"/> to avoid the high false-positive rate of
    /// enabling every national identifier at once.
    /// </summary>
    public static IReadOnlyList<EntityRecognizer> CreateDefault(string language = "en") =>
    [
        .. CreateGeneric(language),
        .. CreateForCountry("us", language),
    ];

    /// <summary>Creates a registry pre-loaded with the default recognizers (generic + US).</summary>
    public static RecognizerRegistry CreateDefaultRegistry(string language = "en") =>
        new(CreateDefault(language));

    /// <summary>
    /// Creates a registry with the generic recognizers, the US pack, and the requested additional
    /// country packs (by ISO 3166-1 alpha-2 code, case-insensitive).
    /// </summary>
    /// <param name="language">The analysis language assigned to every recognizer.</param>
    /// <param name="countries">Additional country packs to enable, or null for none beyond US.</param>
    public static RecognizerRegistry CreateRegistry(string language = "en", IReadOnlyList<string>? countries = null)
    {
        var recognizers = new List<EntityRecognizer>(CreateDefault(language));

        if (countries is { Count: > 0 })
        {
            // dedup on the resolved pack, not the raw code, so aliases (e.g. "gb"/"uk") and the
            // always-on US pack are never added twice
            var seen = new HashSet<string>(StringComparer.Ordinal) { "us" };
            foreach (var country in countries)
            {
                if (seen.Add(CanonicalCountry(country)))
                {
                    recognizers.AddRange(CreateForCountry(country, language));
                }
            }
        }

        return new RecognizerRegistry(recognizers);
    }

    /// <summary>Creates the generic (country-agnostic) recognizers for the given language.</summary>
    public static IReadOnlyList<EntityRecognizer> CreateGeneric(string language = "en") =>
    [
        new CreditCardRecognizer(supportedLanguage: language),
        new EmailRecognizer(supportedLanguage: language),
        new IbanRecognizer(supportedLanguage: language),
        new CryptoRecognizer(supportedLanguage: language),
        new IpRecognizer(supportedLanguage: language),
        new UrlRecognizer(supportedLanguage: language),
        new MacAddressRecognizer(supportedLanguage: language),
        new PhoneRecognizer(supportedLanguage: language),
    ];

    // maps aliases to a single canonical pack code so a pack is never selected twice
    private static string CanonicalCountry(string country)
    {
        var code = country.ToLowerInvariant();
        return code == "gb" ? "uk" : code;
    }

    /// <summary>
    /// Creates the recognizer pack for a single country (by ISO 3166-1 alpha-2 code,
    /// case-insensitive). Returns an empty list for an unknown code.
    /// </summary>
    public static IReadOnlyList<EntityRecognizer> CreateForCountry(string country, string language = "en") =>
        CanonicalCountry(country) switch
        {
            "us" =>
            [
                new UsSsnRecognizer(supportedLanguage: language),
                new UsItinRecognizer(supportedLanguage: language),
                new AbaRoutingRecognizer(supportedLanguage: language),
                new UsBankRecognizer(supportedLanguage: language),
                new UsDriverLicenseRecognizer(supportedLanguage: language),
                new UsPassportRecognizer(supportedLanguage: language),
                new UsNpiRecognizer(supportedLanguage: language),
                new UsMbiRecognizer(supportedLanguage: language),
                new MedicalLicenseRecognizer(supportedLanguage: language),
            ],
            "uk" =>
            [
                new UkNinoRecognizer(supportedLanguage: language),
                new UkNhsRecognizer(supportedLanguage: language),
                new UkPostcodeRecognizer(supportedLanguage: language),
                new UkPassportRecognizer(supportedLanguage: language),
                new UkDrivingLicenceRecognizer(supportedLanguage: language),
                new UkVehicleRegistrationRecognizer(supportedLanguage: language),
            ],
            "de" =>
            [
                new DeIdCardRecognizer(supportedLanguage: language),
                new DeTaxIdRecognizer(supportedLanguage: language),
                new DePassportRecognizer(supportedLanguage: language),
                new DePlzRecognizer(supportedLanguage: language),
                new DeSocialSecurityRecognizer(supportedLanguage: language),
                new DeVatIdRecognizer(supportedLanguage: language),
                new DeFuehrerscheinRecognizer(supportedLanguage: language),
                new DeKfzRecognizer(supportedLanguage: language),
                new DeTaxNumberRecognizer(supportedLanguage: language),
                new DeHandelsregisterRecognizer(supportedLanguage: language),
            ],
            "in" =>
            [
                new InAadhaarRecognizer(supportedLanguage: language),
                new InPanRecognizer(supportedLanguage: language),
                new InGstinRecognizer(supportedLanguage: language),
                new InPassportRecognizer(supportedLanguage: language),
                new InVoterRecognizer(supportedLanguage: language),
                new InVehicleRegistrationRecognizer(supportedLanguage: language),
            ],
            "it" =>
            [
                new ItFiscalCodeRecognizer(supportedLanguage: language),
                new ItVatCodeRecognizer(supportedLanguage: language),
                new ItDriverLicenseRecognizer(supportedLanguage: language),
                new ItIdentityCardRecognizer(supportedLanguage: language),
                new ItPassportRecognizer(supportedLanguage: language),
            ],
            "es" =>
            [
                new EsNifRecognizer(supportedLanguage: language),
                new EsNieRecognizer(supportedLanguage: language),
                new EsPassportRecognizer(supportedLanguage: language),
            ],
            _ => [],
        };
}
