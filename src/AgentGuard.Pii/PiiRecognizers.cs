using AgentGuard.Pii.Analyzer;
using AgentGuard.Pii.Recognizers.Generic;
using AgentGuard.Pii.Recognizers.Us;

namespace AgentGuard.Pii;

/// <summary>Factory for the Stage 1 set of built-in recognizers.</summary>
public static class PiiRecognizers
{
    /// <summary>Creates the default Stage 1 recognizers for the given language.</summary>
    public static IReadOnlyList<EntityRecognizer> CreateDefault(string language = "en") =>
    [
        new CreditCardRecognizer(supportedLanguage: language),
        new EmailRecognizer(supportedLanguage: language),
        new IbanRecognizer(supportedLanguage: language),
        new CryptoRecognizer(supportedLanguage: language),
        new IpRecognizer(supportedLanguage: language),
        new UrlRecognizer(supportedLanguage: language),
        new MacAddressRecognizer(supportedLanguage: language),
        new PhoneRecognizer(supportedLanguage: language),
        new UsSsnRecognizer(supportedLanguage: language),
        new UsItinRecognizer(supportedLanguage: language),
    ];

    /// <summary>Creates a registry pre-loaded with the default Stage 1 recognizers.</summary>
    public static RecognizerRegistry CreateDefaultRegistry(string language = "en") =>
        new(CreateDefault(language));
}
