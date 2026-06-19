using AgentGuard.Pii.Analyzer;

namespace AgentGuard.Pii.Recognizers.Generic;

/// <summary>
/// Recognizes email addresses using a regex, validating that the domain has a fully-qualified
/// name.
/// </summary>
public sealed class EmailRecognizer : PatternRecognizer
{
    private static readonly IReadOnlyList<Pattern> DefaultPatterns =
    [
        new Pattern(
            "Email (Medium)",
            @"\b((([!#$%&'*+\-/=?^_`{|}~\w])|([!#$%&'*+\-/=?^_`{|}~\w][!#$%&'*+\-/=?^_`{|}~\.\w]{0,}[!#$%&'*+\-/=?^_`{|}~\w]))[@]\w+([-.]\w+)*\.\w+([-.]\w+)*)\b",
            0.5),
    ];

    private static readonly IReadOnlyList<string> DefaultContext = ["email"];

    /// <summary>Initializes a new instance of the <see cref="EmailRecognizer"/> class.</summary>
    public EmailRecognizer(string supportedEntity = "EMAIL_ADDRESS", string supportedLanguage = "en")
        : base(supportedEntity, patterns: DefaultPatterns, context: DefaultContext, supportedLanguage: supportedLanguage)
    {
    }

    /// <inheritdoc />
    public override bool? ValidateResult(string patternText)
    {
        var atIndex = patternText.LastIndexOf('@');
        if (atIndex <= 0 || atIndex == patternText.Length - 1)
        {
            return false;
        }

        var domain = patternText[(atIndex + 1)..];
        var dotIndex = domain.LastIndexOf('.');
        if (dotIndex <= 0 || dotIndex == domain.Length - 1)
        {
            return false;
        }

        var tld = domain[(dotIndex + 1)..];
        return tld.Length >= 2 && tld.All(char.IsLetter);
    }
}
