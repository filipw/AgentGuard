using System.Text.RegularExpressions;
using AgentGuard.Core.Abstractions;

using AgentGuard.Core.Rules;

namespace AgentGuard.Core.Rules.PromptInjection;

/// <summary>How aggressively <see cref="PromptInjectionRule"/> matches. Higher tiers add lower-precision patterns.</summary>
public enum Sensitivity
{
    /// <summary>
    /// Highest-confidence patterns only, minimal false positives: instruction overrides, personas
    /// without rules, attempts to switch off the assistant's safeguards, forged turns that carry a
    /// directive, chat-template tokens and frames.
    /// </summary>
    Low,

    /// <summary>
    /// Adds system-prompt extraction, forged assistant turns, jailbreak keywords, standing orders to
    /// obey, coercion and contradiction patterns. The default.
    /// </summary>
    Medium,

    /// <summary>
    /// Adds plain role play ("pretend you are ..."), framing, inversion, link injection, bare chat-role
    /// markers, system-role JSON objects and any standing order ("from now on you should ...").
    /// Trades precision for recall: ordinary requests and pasted logs or API payloads match here.
    /// </summary>
    High
}

/// <summary>Options for <see cref="PromptInjectionRule"/>.</summary>
public sealed class PromptInjectionOptions
{
    /// <summary>Which pattern tiers to run. Default: <see cref="Sensitivity.Medium"/>.</summary>
    public Sensitivity Sensitivity { get; init; } = Sensitivity.Medium;

    /// <summary>
    /// Additional regex patterns to match, beyond the built-in tiers. Validated and compiled when the
    /// rule is constructed, so an invalid pattern fails at startup rather than on the first request.
    /// </summary>
    public IList<string> CustomPatterns { get; init; } = [];

    /// <summary>When true (default), run the system-prompt extraction patterns.</summary>
    public bool BlockSystemPromptExtraction { get; init; } = true;

    /// <summary>When true (default), run the role/persona hijacking patterns.</summary>
    public bool BlockRolePlayAttacks { get; init; } = true;

    /// <summary>
    /// What to do when a pattern exceeds <see cref="MatchTimeout"/> and no other pattern matched.
    /// Default: <see cref="ErrorBehavior.FailOpen"/>, matching the other detection rules. Set to
    /// <see cref="ErrorBehavior.FailClosed"/> when a scan that cannot complete should block.
    /// </summary>
    /// <remarks>
    /// A timeout does not end the scan: the remaining patterns still run and the rule blocks if any
    /// of them matches, so this only decides the outcome when every pattern that did finish came
    /// back clean.
    /// </remarks>
    public ErrorBehavior OnError { get; init; } = ErrorBehavior.FailOpen;

    /// <summary>
    /// Per-pattern match timeout. Default: 250 ms.
    /// </summary>
    /// <remarks>
    /// This bounds a single pattern. A pattern that times out is recorded and the scan carries on
    /// with the rest, so the whole-rule worst case is the number of patterns times this budget. The
    /// built-in patterns run in time linear in the input, and a warm evaluation of all of them
    /// takes roughly 0.01 ms on a typical prompt, so in practice only a very large input or a
    /// pathological custom pattern reaches the budget; bound input size upstream (for example with
    /// a token limit) if that matters. It is set well above the steady-state cost because the first
    /// match on a compiled pattern also pays IL generation, and a tighter budget turned a cold start
    /// into a skipped check.
    /// </remarks>
    public TimeSpan MatchTimeout { get; init; } = TimeSpan.FromMilliseconds(250);
}

/// <summary>The kind of attack a built-in pattern detects, used to honour the per-category options.</summary>
internal enum InjectionPatternCategory
{
    General,
    SystemPromptExtraction,
    RolePlay
}

/// <summary>
/// Regex-based prompt injection detection. Order 10 - runs before the ML classifiers so an obvious
/// attack is rejected without paying for inference.
/// </summary>
/// <remarks>
/// All built-in patterns are compiled once into static arrays. Earlier revisions called the static
/// <see cref="Regex"/> helpers, which share a 15-entry cache across the process - with roughly sixty
/// patterns that cache thrashes and every evaluation re-parses nearly all of them.
/// </remarks>
public sealed class PromptInjectionRule : IGuardrailRule
{
    private readonly PromptInjectionOptions _options;
    private readonly (Regex Pattern, GuardrailSeverity Severity)[] _builtInPatterns;
    private readonly Regex[] _customPatterns;

    // Patterns informed by the Arcanum Prompt Injection Taxonomy
    // (https://github.com/Arcanum-Sec/arc_pi_taxonomy, CC BY 4.0)
    //
    // Organized into three tiers. Low sensitivity uses only CorePatterns (highest-confidence
    // detections with minimal false positives). Medium adds MediumPatterns. High adds all.

    private const RegexOptions Opts =
        RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant;

    // the compile-time timeout only bounds the shared static instances; a rule configured with a
    // different MatchTimeout recompiles its own set (see BuildPatterns).
    private static readonly TimeSpan DefaultTimeout = TimeSpan.FromMilliseconds(250);

    // the phrase building blocks shared with the tool-result rule
    private const string Determiners = InjectionPhrases.Determiners;
    private const string Earlier = InjectionPhrases.Earlier;
    private const string Directives = InjectionPhrases.Directives;
    private const string OverrideVerbs = InjectionPhrases.OverrideVerbs;
    private const string AiSafeguards = InjectionPhrases.AiSafeguards;

    // "pretend you are a ..." is ordinary role play; these make it a request to drop the rules
    private const string Unbound =
        @"(?:unrestricted|unfiltered|uncensored|jailbroken|evil|malicious|rogue|compromised|harmful|dangerous|(?-i:DAN)\b|not\s+an?\s+ai\b|(?:without|with\s+no|no)\s+(?:\w+\s+){0,2}(?:rules|restrictions|filters|limits|limitations|guidelines|guardrails|morals|ethics|boundaries))";

    // the start of a line or sentence, as a lookbehind: it is only checked once the words after it
    // are found, and its indent cannot cross a newline, which keeps the scan linear
    private const string SentenceStart = @"(?<=(?:^|[\n.!?;])[^\S\n]*)";
    private const string LineStart = @"(?<=(?:^|\n)[^\S\n]*)";

    // after "what are your rules" and the like: the question is about a topic, not about the prompt
    private const string NotAboutATopic = @"(?!\s+(?:for|on|about|regarding|around|when|if|to\s+\w+)\b)";

    /// <summary>Core patterns: direct instruction override, unbounded personas, end sequences, variable expansion, security bypass, forged turns.</summary>
    private static readonly (string Pattern, InjectionPatternCategory Category)[] CoreSources =
    [
        // Direct instruction override: verb, optional determiners, a word marking the instructions as
        // the ones in place, and what they are - "ignore all of the previous instructions",
        // "disregard any prior rules", "forget your earlier guidelines"
        (InjectionPhrases.OverrideOfEarlierDirectives, InjectionPatternCategory.General),
        // the same aimed at the assistant's own: "disregard your instructions", "bypass all of your rules"
        (InjectionPhrases.OverrideOfOwnDirectives, InjectionPatternCategory.General),
        // "ignore the above and ...", "disregard everything above" - unless the above is a thing ("the above email")
        (InjectionPhrases.OverrideOfTheAbove, InjectionPatternCategory.General),
        // "forget everything you were told", "ignore all you have been instructed"
        (InjectionPhrases.OverrideOfWhatWasTold, InjectionPatternCategory.General),
        ($@"{SentenceStart}(?:your\s+|here\s+are\s+(?:your\s+)?)?new\s+(?:instructions|rules|persona|directives?|task)\s*:", InjectionPatternCategory.General),
        (@"override\s+(?:instructions|guidelines|system\s+prompt)", InjectionPatternCategory.General),
        // a system prompt being supplied, not talked about: at the start of a line, or announced as new
        ($@"{LineStart}system\s*prompt\s*:", InjectionPatternCategory.General),
        (@"\b(?:new|updated|revised|real|actual|replacement)\s+system\s*prompt\s*:", InjectionPatternCategory.General),

        // Role/persona hijacking, where the persona is one without rules. Plain role play
        // ("pretend you are an interviewer") is in the high tier.
        ($@"you\s+are\s+now\s+(?:an?\s+|the\s+|in\s+)?(?:\w+\s+){{0,4}}{Unbound}", InjectionPatternCategory.RolePlay),
        ($@"pretend\s+(?:that\s+)?(?:you(?:'re|\s+are)|to\s+be)\s+(?:\w+\s+){{0,4}}{Unbound}", InjectionPatternCategory.RolePlay),
        ($@"act\s+as\s+(?:if\s+you\s+(?:are|were)\s+)?(?:an?\s+|the\s+)?(?:\w+\s+){{0,2}}{Unbound}", InjectionPatternCategory.RolePlay),
        (@"you\s+are\s+(?:now\s+)?(?:going\s+to\s+(?:be|act\s+as|pretend\s+to\s+be)\s+)?(?-i:DAN)\b", InjectionPatternCategory.RolePlay),
        // developer mode jailbreak
        (@"developer\s+mode\s+(is\s+)?(now\s+)?(enabled?|activated?|on)", InjectionPatternCategory.RolePlay),

        // Security bypass - direct attempts to disable the assistant's safety mechanisms. Each needs
        // either a noun that only an AI system has (guardrails, safety filters) or the assistant as
        // the owner ("your restrictions"), so "disable the filter in Excel" is not one.
        ($@"\b(?:bypass|disable|turn\s+off|switch\s+off|deactivate|remove|circumvent|evade)\s+(?:(?:all|any|the|your|these|those)\s+){{0,2}}{AiSafeguards}", InjectionPatternCategory.General),
        (@"\b(?:bypass|disable|turn\s+off|switch\s+off|deactivate|remove|circumvent|evade)\s+(?:all\s+(?:of\s+)?)?(?:your|its)\s+(?:\w+\s+){0,2}(?:safety|security|filters?|restrictions?|protections?|limitations?|limits|rules|moderation)\b", InjectionPatternCategory.General),
        (@"\b(?:bypass|disable|remove)\s+(?:(?:all|any|the)\s+){0,2}(?:restrictions?|limitations?|filters?|rules)\s+(?:on|of|in)\s+(?:this|the|your)\s+(?:model|ai|assistant|chatbot|bot|llm)\b", InjectionPatternCategory.General),
        (@"ignore\s+(?:(?:the|your|all|any)\s+){0,2}(safety|security|ethical)\s+(guidelines?|rules?|restrictions?|measures?)", InjectionPatternCategory.General),
        (@"(?:uncensored|unfiltered|unrestricted)\s+(?:mode|persona)\b", InjectionPatternCategory.General),
        (@"\b(?:give|provide|write|generate|produce|switch\s+to|enter|enable|activate|use)\s+(?:me\s+)?(?:with\s+)?(?:an?\s+|the\s+)?(?:uncensored|unfiltered|unrestricted)\s+(?:mode|response|answer|reply|output|version)\b", InjectionPatternCategory.General),
        // "answer without any restrictions", "respond with no guardrails"
        (@"\b(?:respond|answer|reply|act|behave|operate|speak|talk|write|generate|comply|function|continue|proceed)\s+(?:\w+\s+){0,3}(?:without|with\s+no|free\s+(?:of|from))\s+(?:(?:any|all|your|the)\s+){0,2}(?:\w+\s+)?(?:restrictions?|limitations?|guardrails?|filters?|censorship|rules|constraints|boundaries|limits)\b", InjectionPatternCategory.General),
        ($@"\b(?:without|no)\s+(?:any\s+)?{AiSafeguards}", InjectionPatternCategory.General),
        (@"\byou\s+(?:have|are\s+(?:bound\s+by|under|subject\s+to))\s+no\s+(?:\w+\s+)?(?:restrictions?|limitations?|rules|guidelines|filters?|constraints|limits|boundaries)\b", InjectionPatternCategory.General),

        // A chat-role marker carrying a directive. The marker alone is weak evidence (see the other
        // tiers): a pasted log or transcript is full of them. Paired with an instruction cue it is a
        // forged turn. A forged user turn is only that when it gives an override.
        (@"(?:^|\n)[ \t]*(?:SYSTEM|DEVELOPER|ASSISTANT|AI)[ \t]*:[ \t]*"
         + @"(?:you\s+(?:are|must|will|shall|should|can|may|have)\b|your\s+(?:new|real|only|task|role|instructions|rules)\b|ignore\b|disregard\b|forget\b|override\b|bypass\b|enable\b|disable\b|activate\b|"
         + @"new\s+(?:instructions?|rules?|persona|task|context|system|prompt|directives?)\b|from\s+now\s+on\b|always\b|never\b|do\s+not\b|don't\b|must\b|act\s+as\b|pretend\b|"
         + @"reveal\b|repeat\b)", InjectionPatternCategory.General),
        (@"(?:^|\n)[ \t]*(?:USER|HUMAN)[ \t]*:[ \t]*(?:ignore|disregard|forget|override|bypass)\b", InjectionPatternCategory.General),
        // a forged assistant turn that starts the answer for the model
        (@"(?:^|\n)[ \t]*(?:ASSISTANT|AI)[ \t]*:[ \t]*(?:here\s+is\b|here's\b|here\s+are\b)", InjectionPatternCategory.General),

        // End sequence injection - 8 closure families from the Arcanum taxonomy
        // Token delimiters
        (@"<\|endoftext\|>", InjectionPatternCategory.General),
        (@"<\|im_start\|>", InjectionPatternCategory.General),
        (@"<\|im_end\|>", InjectionPatternCategory.General),
        (@"<\|eot_id\|>", InjectionPatternCategory.General),
        (@"<\|start_header_id\|>", InjectionPatternCategory.General),
        // Fake chat roles (require line-start position to avoid matching in-prose references). An
        // INI file's [System] section, which is followed by a key=value line, is not one.
        ($@"{LineStart}\[system\](?![ \t]*\r?\n[ \t]*[\w.-]+[ \t]*=)", InjectionPatternCategory.General),
        ($@"{LineStart}<\s*system\s*>", InjectionPatternCategory.General),
        (@"\[\s*INST\s*\]", InjectionPatternCategory.General),
        (@"\[/\s*INST\s*\]", InjectionPatternCategory.General),
        (@"<<\s*SYS\s*>>", InjectionPatternCategory.General),
        (@"<\|assistant\|>", InjectionPatternCategory.General),
        (@"<\|user\|>", InjectionPatternCategory.General),
        // Bracketed frames
        (@"\[START\s+(OUTPUT|INSTRUCTIONS|SYSTEM)\]", InjectionPatternCategory.General),
        (@"\[END\s+(OUTPUT|INSTRUCTIONS|SYSTEM)\]", InjectionPatternCategory.General),
        // Soft boundaries used as context separators. The frame has to name the system or its
        // instructions and be closed, so a PEM header or "===== END OF REPORT =====" is not one.
        (@"[-=]{5,}[ \t]*(?:(?:BEGIN|END|START)[ \t]+(?:OF[ \t]+)?)?(?:SYSTEM(?:[ \t]+(?:PROMPT|MESSAGE|INSTRUCTIONS?|OVERRIDE))?|(?:NEW[ \t]+)?INSTRUCTIONS?|PROMPT|OVERRIDE|RESET)[ \t]*[-=]{3,}", InjectionPatternCategory.General),
        // a heading that is nothing but such a name: "### SYSTEM", not "### System Requirements"
        ($@"{LineStart}#{{2,}}[ \t]*(?:(?:BEGIN|END|START|NEW)[ \t]+(?:OF[ \t]+)?)?(?:SYSTEM(?:[ \t]+(?:PROMPT|MESSAGE|INSTRUCTIONS?|OVERRIDE))?|NEW[ \t]+INSTRUCTIONS?|OVERRIDE|RESET)[ \t]*:?[ \t]*#*[ \t]*(?=\r?\n|$)", InjectionPatternCategory.General),

        // HTML comment injection - hidden directives in document content. The body is bounded and ends
        // at the next "<!--", so a long line of unclosed "<!-- system" openers is scanned once.
        (@"<!--\s*(?:system|ignore|instruction|prompt|override)(?:[^<>\n]|<(?!!--)){0,200}?-->", InjectionPatternCategory.General),

        // Variable expansion attacks
        (@"\$\{(system_prompt|instructions|config|prompt)\}", InjectionPatternCategory.General),
        (@"\{\{(system_prompt|instructions|config|prompt)\}\}", InjectionPatternCategory.General),
        (@"%\{(system_prompt|instructions|config|prompt)\}", InjectionPatternCategory.General),
    ];

    /// <summary>Medium patterns: system prompt extraction, forged assistant turns, jailbreak, rule addition, anti-harm coercion, contradiction.</summary>
    private static readonly (string Pattern, InjectionPatternCategory Category)[] MediumSources =
    [
        // System prompt extraction. What is asked for has to be the assistant's own prompt: "what are
        // your rules for returns" and "print the assembly instructions" ask about something else.
        ($@"what\s+(?:is|are|was|were)\s+your\s+(?:(?:exact|initial|original|full|complete|hidden|secret|internal|system|current|underlying)\s+){{0,2}}(?:instructions|prompt|rules|directives)\b{NotAboutATopic}", InjectionPatternCategory.SystemPromptExtraction),
        (@"(?:show|reveal|display|print|output|repeat|share|leak|dump|disclose|tell\s+me|give\s+me)\s+(?:\w+\s+){0,3}system\s+(?:prompt|instructions)", InjectionPatternCategory.SystemPromptExtraction),
        ($@"(?:show|reveal|display|print|output|repeat|extract|dump|leak|share|disclose|recite|tell\s+me|give\s+me)\s+(?:me\s+)?(?:(?:all|of|the|exact|entire|full|complete)\s+){{0,3}}(?:your|the\s+(?:assistant|ai|model|bot)(?:'s)?)\s+(?:(?:own|exact|initial|original|full|complete|hidden|secret|internal|system|current|underlying|first)\s+){{0,3}}(?:prompt|instructions|directives|guidelines|rules)\b{NotAboutATopic}", InjectionPatternCategory.SystemPromptExtraction),
        ($@"(?:show|reveal|display|print|output|repeat|extract|dump|leak)\s+(?:me\s+)?the\s+(?:(?:exact|initial|original|hidden|secret|internal|underlying)\s+){{1,3}}(?:prompt|instructions)\b{NotAboutATopic}", InjectionPatternCategory.SystemPromptExtraction),
        (@"repeat\s+(your\s+)?(initial|original|system)\s+(\w+\s+){0,5}(prompt|instructions|message)", InjectionPatternCategory.SystemPromptExtraction),

        // A forged assistant turn - a user message that speaks as the model. "Assistant:" at the start
        // of a line also opens every pasted transcript, which is why it is not in the core tier; the
        // variants that carry a directive or start the answer are.
        (@"(?:^|\n)[ \t]*ASSISTANT[ \t]*:[ \t]*\S", InjectionPatternCategory.General),

        // A model or persona described as having no rules, the way jailbreak prompts introduce theirs:
        // "BOB is a chatbot without restrictions", "always sends the unfiltered response"
        (@"\b(?:uncensored|unfiltered)\s+(?:responses?|answers?|repl(?:y|ies)|model|ai|assistant|chatbot)\b", InjectionPatternCategory.General),
        (@"\b(?:chatbot|ai|assistant|model|bot|persona|character)\s+(?:\w+\s+){0,3}(?:without|with\s+(?:absolutely\s+)?no)\s+(?:any\s+)?(?:restrictions?|limitations?|rules|filters?|limits|boundaries|guidelines)\b", InjectionPatternCategory.General),
        (@"\b(?:say|do)\s+(?:or\s+(?:say|do)\s+)?anything\s+(?:\w+\s+){0,3}(?:without|with\s+(?:absolutely\s+)?no)\s+(?:any\s+)?(?:restrictions?|limitations?|rules|filters?|limits|boundaries)\b", InjectionPatternCategory.General),

        // Jailbreak keywords. Jailbreaking a phone or a console is a different subject.
        (@"DAN\s+mode", InjectionPatternCategory.General),
        (@"(?<!\b(?:iphone|ipad|ipod|ios|phone|device|console|kindle|firestick|android|ps[345]|playstation|switch|roku)\s+)jailbr(?:eak|oken|eaking)"
         + @"(?!\s+(?:(?:my|an?|the|your|this|that|his|her|their|our)\s+)?(?:\w+\s+)?(?:iphones?|ipads?|ipods?|ios|phones?|devices?|kindles?|firesticks?|fire\s+tv|consoles?|ps[345]|playstation|switch|roku|chromecast|apple\s+tv|tablets?|android)\b)",
            InjectionPatternCategory.General),
        ($@"(?:{SentenceStart}|\b(?:stands?\s+for|can|could|to)\s+[""'\u201C]?|\(\s*)do\s+anything\s+now\b", InjectionPatternCategory.General),

        // Rule addition / modification
        ($@"{SentenceStart}(?:new|additional|updated)\s+rule\s*:", InjectionPatternCategory.General),
        // a standing order to obey or to drop the rules - not a preference ("from now on you should
        // answer in French"). The optional comma owns the whitespace after it, which keeps the scan linear.
        (@"(?:from\s+now\s+on|henceforth|going\s+forward)\s*(?:,\s*)?(?:you\s+)?(?:must|should|will|shall)\s+(?:\w+\s+){0,3}"
         + @"(?:obey|comply|ignore|disregard|forget|bypass|pretend|(?:never|not)\s+refuse|no\s+longer|stop\s+following|act\s+as|answer\s+(?:all|every|any)|do\s+(?:anything|whatever|everything|as)|respond\s+(?:without|only\s+as|as\s+if)|follow\s+(?:the\s+following|these|this|my)\s+(?:\w+\s+)?(?:rules?|ruleset|instructions?|commands?|orders?))\b",
            InjectionPatternCategory.General),

        // Anti-harm coercion - pressuring the model to override safety by framing refusal as harmful
        (@"(refusing|failure)\s+to\s+(comply|help|assist|respond)\s+(is|would\s+be|causes?)(\s+\w+){0,5}\s+(harmful|dangerous|unethical|immoral|harm)", InjectionPatternCategory.General),
        (@"you\s+(must|have\s+to|need\s+to)\s+(comply|obey|help|answer)\s+(or|otherwise)", InjectionPatternCategory.General),
        (@"it\s+would\s+be\s+(unethical|immoral|wrong|harmful)\s+(not\s+to|to\s+refuse|to\s+decline)", InjectionPatternCategory.General),
        (@"(ethical|moral)\s+(duty|obligation|imperative)\s+to\s+(help|comply|answer|respond)", InjectionPatternCategory.General),
        (@"(people|someone|lives?)\s+(will|could|might)\s+(be\s+)?(hurt|harmed|die|suffer)\s+if\s+you\s+(don't|do\s+not|refuse)", InjectionPatternCategory.General),

        // Contradiction - presenting conflicting instructions to confuse safety logic
        (@"your\s+(actual|real|true|original)\s+(instructions|rules|purpose)\s+(are|is|say)", InjectionPatternCategory.General),
        (@"(the\s+)?(previous|above)\s+(instructions?|rules?)\s+(are|were|was)\s+(wrong|incorrect|fake|a\s+test)", InjectionPatternCategory.General),
        (@"(contrary\s+to|despite|regardless\s+of)\s+(what|your)\s+(you\s+were|previous|system)\s+(told|instructions|prompt)", InjectionPatternCategory.General),
    ];

    /// <summary>High-sensitivity patterns: plain role play, framing attacks, inversion, double-negative extraction, link injection, bare role markers, role objects, standing orders.</summary>
    private static readonly (string Pattern, InjectionPatternCategory Category)[] HighSources =
    [
        // Plain role play addressed to the assistant - "pretend you are an interviewer" as much as
        // "pretend you are my late grandmother". Membership and status ("you are now a member") is
        // not a persona. The personas without rules are in the core tier.
        (@"you\s+are\s+now\s+an?\s+(?!(?:member|subscriber|customer|owner|part|participant|user|admin(?:istrator)?|moderator|contributor|collaborator|proud|registered|verified|certified|official|premium|gold|silver)\b)", InjectionPatternCategory.RolePlay),
        (@"pretend\s+(?:that\s+)?you(?:'re|\s+are)\s+", InjectionPatternCategory.RolePlay),
        ($@"(?:{SentenceStart}|\b(?:please|now|and|then|just|you\s+(?:will|must|should|can|shall))\s+)pretend\s+to\s+be\s+", InjectionPatternCategory.RolePlay),
        (@"act\s+as\s+if\s+you\s+(are|were)\s+", InjectionPatternCategory.RolePlay),

        // Framing attacks
        (@"(imagine|suppose|assume)\s+you\s+(are|have|were)\s+(an?\s+)?(unrestricted|unfiltered|uncensored)", InjectionPatternCategory.RolePlay),
        (@"for\s+a\s+fictional\s+(story|scenario|world)\s+where", InjectionPatternCategory.RolePlay),
        (@"in\s+a\s+hypothetical\s+(scenario|world)\s+where\s+(there\s+are\s+)?no\s+(rules|restrictions|limits)", InjectionPatternCategory.RolePlay),

        // Inversion / double-negative extraction
        (@"what\s+would\s+you\s+(not|never)\s+do\s+if", InjectionPatternCategory.SystemPromptExtraction),
        (@"list\s+(the\s+)?(things|topics)\s+you('re|\s+are)\s+(forbidden|not\s+allowed|unable)", InjectionPatternCategory.SystemPromptExtraction),

        // Link injection - malicious directives embedded in URLs or references. The link body is
        // bounded so an unclosed bracket cannot drive a quadratic scan, and the URL form starts only at
        // the beginning of a non-space run and commits to the first scheme in it.
        (@"(?<!\S)(?>\S*?https?://)\S*?(system_prompt|ignore_rules|jailbreak|override|injection)", InjectionPatternCategory.General),
        // the keyword search is atomic: if the link does not close within reach of the keyword nearest
        // the closing parenthesis, it cannot for any earlier one either, so those are not retried. The
        // link text ends at the next "[" and the target at the next "](", so a run of unclosed links is
        // scanned once.
        (@"\[[^\[\]\n]{0,200}\]\((?>(?:[^)\]\n]|\](?!\()){0,200}(ignore|override|system|jailbreak|injection))(?:[^)\]\n]|\](?!\()){0,200}\)", InjectionPatternCategory.General),

        // Bare chat-role markers. Weak evidence on their own - a pasted log line ("System: the build
        // failed") or a support transcript ("User: hi / Agent: hello") trips them - so they only run
        // at the tier that explicitly trades precision for recall. The marker-plus-directive variants
        // in CoreSources cover the high-confidence cases. Line starts use the same linear lookbehind
        // as the fake chat roles above.
        ($@"{LineStart}SYSTEM\s*:", InjectionPatternCategory.General),
        ($@"{LineStart}USER\s*:", InjectionPatternCategory.General),
        ($@"{LineStart}HUMAN\s*:", InjectionPatternCategory.General),
        ($@"{LineStart}DEVELOPER\s*:", InjectionPatternCategory.General),
        ($@"{LineStart}(?:AI|BOT|MODEL)[ \t]*:[ \t]*\S", InjectionPatternCategory.General),

        // A chat message object with the system role. It is how a forged system turn is written in
        // JSON, and also what every developer pastes when asking about an API call.
        (@"""role""\s*:\s*""system""", InjectionPatternCategory.General),

        // Any standing order, including the ordinary ones ("from now on you should answer in French")
        (@"(from\s+now\s+on|henceforth|going\s+forward)\s*(?:,\s*)?(you\s+)?(must|should|will|shall)", InjectionPatternCategory.General),

        // Bare restriction-free phrasing at the end of a clause ("... with no limitations.")
        (@"(without|no)\s+(any\s+)?(restrictions?|limitations?)\s*($|[.,;!?])", InjectionPatternCategory.General),
    ];

    private static readonly Regex[] CoreDefault = Compile(CoreSources, DefaultTimeout);
    private static readonly Regex[] MediumDefault = Compile(MediumSources, DefaultTimeout);
    private static readonly Regex[] HighDefault = Compile(HighSources, DefaultTimeout);

    /// <summary>Initializes a new instance of the <see cref="PromptInjectionRule"/> class.</summary>
    /// <param name="options">Configuration. When null, defaults are used.</param>
    /// <exception cref="ArgumentException">A custom pattern is not a valid regular expression.</exception>
    public PromptInjectionRule(PromptInjectionOptions? options = null)
    {
        _options = options ?? new();

        if (_options.MatchTimeout <= TimeSpan.Zero)
            throw new ArgumentException("MatchTimeout must be greater than zero.", nameof(options));

        _builtInPatterns = BuildPatterns(_options);
        _customPatterns = CompileCustom(_options);
    }

    /// <inheritdoc />
    public string Name => "prompt-injection";

    /// <inheritdoc />
    public GuardrailPhase Phase => GuardrailPhase.Input;

    /// <inheritdoc />
    public int Order => 10;

    /// <inheritdoc />
    public ValueTask<GuardrailResult> EvaluateAsync(GuardrailContext context, CancellationToken cancellationToken = default)
    {
        var text = context.Text;
        if (string.IsNullOrWhiteSpace(text))
            return ValueTask.FromResult(GuardrailResult.Passed());

        // a pattern that cannot finish within MatchTimeout is a scan we could not complete, not a
        // verdict: the remaining patterns still run and any of them can block. OnError decides only
        // when nothing matched.
        var timedOut = 0;

        foreach (var (pattern, severity) in _builtInPatterns)
        {
            switch (TryIsMatch(pattern, text))
            {
                case true:
                    return ValueTask.FromResult(
                        GuardrailResult.Blocked("Potential prompt injection detected.", severity));
                case null:
                    timedOut++;
                    break;
            }
        }

        foreach (var pattern in _customPatterns)
        {
            switch (TryIsMatch(pattern, text))
            {
                case true:
                    return ValueTask.FromResult(
                        GuardrailResult.Blocked("Input matched a custom injection pattern.", GuardrailSeverity.High));
                case null:
                    timedOut++;
                    break;
            }
        }

        if (timedOut > 0)
        {
            return ValueTask.FromResult(GuardrailResult.Error(
                Name, _options.OnError,
                $"{timedOut} pattern(s) exceeded the {_options.MatchTimeout.TotalMilliseconds:F0} ms match timeout and no other pattern matched"));
        }

        return ValueTask.FromResult(GuardrailResult.Passed());
    }

    /// <summary>Matches, returning <c>null</c> rather than throwing when the pattern times out.</summary>
    private static bool? TryIsMatch(Regex pattern, string text)
    {
        try
        {
            return pattern.IsMatch(text);
        }
        catch (RegexMatchTimeoutException)
        {
            return null;
        }
        catch (IndexOutOfRangeException)
        {
            // the compiled regex engine has thrown this from inside a match on a pattern with nested
            // lazy loops; a pattern that cannot be evaluated is a scan that did not complete
            return null;
        }
    }

    private static Regex[] Compile((string Pattern, InjectionPatternCategory Category)[] sources, TimeSpan timeout)
    {
        var compiled = sources.Select(s => new Regex(s.Pattern, Opts, timeout)).ToArray();

        // compiled patterns generate IL on first use, inside the match timeout; pay it here
        RegexPatterns.Warm(compiled);
        return compiled;
    }

    private static (Regex, GuardrailSeverity)[] BuildPatterns(PromptInjectionOptions options)
    {
        var useDefaults = options.MatchTimeout == DefaultTimeout;

        var tiers = new List<((string, InjectionPatternCategory)[] Sources, Regex[] Compiled, GuardrailSeverity Severity)>
        {
            (CoreSources, CoreDefault, GuardrailSeverity.Critical),
        };

        if (options.Sensitivity is Sensitivity.Medium or Sensitivity.High)
            tiers.Add((MediumSources, MediumDefault, GuardrailSeverity.High));

        if (options.Sensitivity is Sensitivity.High)
            tiers.Add((HighSources, HighDefault, GuardrailSeverity.High));

        var result = new List<(Regex, GuardrailSeverity)>();
        foreach (var (sources, compiled, severity) in tiers)
        {
            var regexes = useDefaults ? compiled : Compile(sources, options.MatchTimeout);
            for (var i = 0; i < sources.Length; i++)
            {
                if (!IsCategoryEnabled(sources[i].Item2, options))
                    continue;
                result.Add((regexes[i], severity));
            }
        }

        return [.. result];
    }

    private static bool IsCategoryEnabled(InjectionPatternCategory category, PromptInjectionOptions options) => category switch
    {
        InjectionPatternCategory.SystemPromptExtraction => options.BlockSystemPromptExtraction,
        InjectionPatternCategory.RolePlay => options.BlockRolePlayAttacks,
        _ => true
    };

    private static Regex[] CompileCustom(PromptInjectionOptions options)
    {
        var compiled = new List<Regex>(options.CustomPatterns.Count);
        foreach (var pattern in options.CustomPatterns)
        {
            try
            {
                compiled.Add(new Regex(pattern, Opts, options.MatchTimeout));
            }
            catch (ArgumentException ex)
            {
                throw new ArgumentException(
                    $"CustomPatterns contains an invalid regular expression: '{pattern}'. {ex.Message}",
                    nameof(options), ex);
            }
        }

        return [.. compiled];
    }
}
