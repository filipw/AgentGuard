namespace AgentGuard.Core.Rules;

/// <summary>
/// The phrase building blocks of an instruction override or a safeguard bypass, as regex fragments.
/// Shared by the rule that reads what a user typed and the rule that reads what a tool returned, so
/// both recognize the same wordings and leave the same ordinary sentences alone.
/// </summary>
internal static class InjectionPhrases
{
    // Building blocks for the override patterns.
    //
    // Determiners are the words that can stand between the verb and its target ("ignore ALL OF THE
    // previous instructions"). "my" and "our" are left out on purpose: "ignore my previous instructions"
    // is a user correcting themselves, not an attack on the system prompt.
    internal const string Determiners =
        @"(?:(?:all|any|every|each|of|the|your|these|those|this|that|its|their)\s+){0,4}";

    // what marks the instructions as the ones already in place
    internal const string Earlier =
        @"(?:previous|prior|above|earlier|preceding|former|initial|original|old|foregoing|aforementioned|existing|system|safety)";

    // what an assistant is run by. Ordinary nouns that follow "previous" in everyday requests (message,
    // email, question, context) are not here, so "ignore the previous email" stays an ordinary sentence.
    internal const string Directives =
        @"(?:instructions?|prompts?|rules?|guidelines?|guidance|directions?|directives?|commands?|orders?|constraints?|restrictions?|programming|training)";

    // a negated verb is the opposite request: "don't forget the previous instructions"
    internal const string OverrideVerbs =
        @"(?<!\b(?:not|never|cannot|\w+n't)\s+)(?:ignore|disregard|forget|override|bypass|(?:do\s+not|don't|never|stop|no\s+longer)\s+follow(?:ing)?)";

    // nouns that only make sense as an AI system's own protections
    internal const string AiSafeguards =
        @"(?:guardrails?|safeguards?|censorship|(?:safety|security|content|ethical|moral)\s+(?:filters?|guardrails?|measures?|protocols?|checks?|restrictions?|protections?|guidelines?|polic(?:y|ies)|mechanisms?|features?|rules?|constraints?))";

    /// <summary>
    /// Verb, optional determiners, a word marking the instructions as the ones in place, and what they
    /// are: "ignore all of the previous instructions", "disregard any prior rules".
    /// </summary>
    internal const string OverrideOfEarlierDirectives =
        @"\b" + OverrideVerbs + @"\s+" + Determiners + Earlier + @"\s+(?:\w+\s+){0,2}" + Directives + @"\b";

    /// <summary>The same aimed at the assistant's own: "disregard your instructions".</summary>
    internal const string OverrideOfOwnDirectives =
        @"\b" + OverrideVerbs + @"\s+(?:all\s+(?:of\s+)?)?your\s+(?:\w+\s+){0,2}" + Directives + @"\b";

    /// <summary>
    /// "ignore the above and ...", "disregard everything above" - unless the above is a thing ("the above email").
    /// </summary>
    internal const string OverrideOfTheAbove =
        @"\b(?:ignore|disregard)\s+(?:all\s+(?:of\s+)?|everything\s+)?(?:the\s+)?above\b"
        + @"(?!\s+(?:e-?mails?|messages?|typos?|comments?|posts?|text|lines?|questions?|requests?|notes?|links?|attachments?|invoices?|figures?|numbers?|quotes?|prices?|address(?:es)?|warnings?|errors?|code|tables?|examples?|paragraphs?|lists?|images?)\b)";

    /// <summary>"forget everything you were told", "ignore all you have been instructed".</summary>
    internal const string OverrideOfWhatWasTold =
        @"\b(?:ignore|disregard|forget)\s+(?:everything|anything|all|whatever)\s+(?:that\s+)?you(?:'ve|\s+have|\s+were|\s+was|\s+had)?\s+(?:been\s+)?(?:told|given|instructed|taught|trained|programmed)\b";

    /// <summary>
    /// An attempt to switch off the assistant's safeguards: a noun only an AI system has (guardrails,
    /// safety filters) or the assistant as the owner ("your restrictions").
    /// </summary>
    internal const string SafeguardBypass =
        @"\b(?:bypass|disable|turn\s+off|switch\s+off|deactivate|remove|circumvent|evade)\s+(?:(?:(?:all|any|the|your|these|those)\s+){0,2}" + AiSafeguards
        + @"|(?:all\s+(?:of\s+)?)?(?:your|its)\s+(?:\w+\s+){0,2}(?:safety|security|filters?|restrictions?|protections?|limitations?|limits|rules|moderation)\b)";
}
