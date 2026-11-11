using AgentGuard.Core.Abstractions;

namespace AgentGuard.RemoteClassifier;

/// <summary>
/// Options for the remote prompt injection rule.
/// </summary>
public sealed class RemotePromptInjectionOptions
{
    /// <summary>
    /// Labels that indicate an injection was detected. Must contain at least one label, and none that
    /// is also in <see cref="SafeLabels"/>. Default: jailbreak, injection, prompt_injection, malicious,
    /// unsafe, harmful, attack, LABEL_1.
    /// </summary>
    /// <remarks>
    /// Labels are compared by their letters and digits only, ignoring case and independently of the
    /// current culture and of whatever comparer the set itself uses, so <c>prompt_injection</c> also
    /// matches <c>prompt-injection</c>, <c>PromptInjection</c> and <c>Prompt Injection</c>.
    /// <c>LABEL_1</c> is what a Hugging Face model without an <c>id2label</c> mapping calls its second
    /// class, which for a binary injection classifier is the injection class; remove it (and
    /// <c>LABEL_0</c> from <see cref="SafeLabels"/>) when the model behind the endpoint numbers its
    /// classes the other way round.
    /// </remarks>
    public ISet<string> InjectionLabels { get; init; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "jailbreak", "injection", "prompt_injection", "malicious", "unsafe", "harmful", "attack", "LABEL_1"
    };

    /// <summary>
    /// Labels that mean the classifier found nothing, compared the same way as
    /// <see cref="InjectionLabels"/>. Must contain at least one label. Default: safe, benign, legit,
    /// legitimate, clean, normal, harmless, LABEL_0.
    /// </summary>
    /// <remarks>
    /// A predicted label that is in neither set is not read as clean: unless a scored injection label
    /// reaches the threshold, the result is an error handled by <see cref="OnError"/>. Add the model's
    /// own labels here when it uses others.
    /// </remarks>
    public ISet<string> SafeLabels { get; init; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "safe", "benign", "legit", "legitimate", "clean", "normal", "harmless", "LABEL_0"
    };

    /// <summary>
    /// Confidence threshold for the injection label (0.0-1.0; NaN is rejected). Input is blocked when an
    /// injection label's score is at or above it: the predicted label's score, or, when the classifier
    /// reports every label's score (<see cref="ClassificationResult.Scores"/>), the injection label's own
    /// score even if another label scored higher. Default: 0.5.
    /// </summary>
    public float Threshold { get; init; } = 0.5f;

    /// <summary>
    /// Whether to include the confidence score and model info in result metadata.
    /// Default: true.
    /// </summary>
    public bool IncludeConfidence { get; init; } = true;

    /// <summary>
    /// What to do when the remote classifier is unreachable, times out, returns an error, returns
    /// a result without a usable label and score, predicts a label that is in neither
    /// <see cref="InjectionLabels"/> nor <see cref="SafeLabels"/>, or the text needs more than
    /// <see cref="MaxRequests"/> requests.
    /// Default: <see cref="ErrorBehavior.FailOpen"/>.
    /// </summary>
    public ErrorBehavior OnError { get; init; } = ErrorBehavior.FailOpen;

    /// <summary>
    /// Backward-compatible alias for <see cref="OnError"/>.
    /// Setting this to true maps to <see cref="ErrorBehavior.FailOpen"/>,
    /// false maps to <see cref="ErrorBehavior.FailClosed"/>.
    /// Prefer using <see cref="OnError"/> directly for the full range of options.
    /// </summary>
    [Obsolete("Use OnError instead. FailOpen = true → OnError = FailOpen, FailOpen = false → OnError = FailClosed.")]
    public bool FailOpen
    {
        get => OnError == ErrorBehavior.FailOpen;
        init => OnError = value ? ErrorBehavior.FailOpen : ErrorBehavior.FailClosed;
    }

    /// <summary>
    /// Timeout for each classification request: a positive time span, or
    /// <c>Timeout.InfiniteTimeSpan</c> for none. Default: 10 seconds.
    /// </summary>
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>
    /// The most characters (UTF-16 code units) sent in one request, at least 1. Longer text is split
    /// into overlapping windows that are classified one request at a time, and an injection found in
    /// any of them blocks. Default: 2,000, which fits the 512-token input of the common
    /// prompt-injection classifiers for ordinary prose.
    /// </summary>
    /// <remarks>
    /// A text-classification model reads a fixed number of tokens and drops, or rejects, the rest, so
    /// text sent whole is judged by its beginning only. Lower the value for text that tokenizes
    /// densely (code, base64, languages written without spaces) and raise it for a model with a
    /// longer input; <see cref="int.MaxValue"/> always sends the text whole.
    /// </remarks>
    public int MaxCharactersPerRequest { get; init; } = 2_000;

    /// <summary>
    /// How many characters consecutive windows share, from 0 to half of
    /// <see cref="MaxCharactersPerRequest"/>, so that an injection lying across a window boundary is
    /// seen whole by one request. Default: null, a fifth of <see cref="MaxCharactersPerRequest"/>
    /// (400 at its default).
    /// </summary>
    public int? WindowOverlapCharacters { get; init; }

    /// <summary>
    /// The most requests made for one evaluation; 0 removes the limit. Text that needs more is an
    /// error handled by <see cref="OnError"/>, unless an injection is found in the part the limit
    /// covers. Default: 32, about 51,000 characters at the default window size.
    /// </summary>
    public int MaxRequests { get; init; } = 32;
}
