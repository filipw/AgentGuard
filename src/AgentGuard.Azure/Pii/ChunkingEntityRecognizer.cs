using TasmanianDevil.Analyzer;

namespace AgentGuard.Azure.Pii;

/// <summary>
/// Decorates a recognizer whose backing service caps the size of the text it accepts, so that longer
/// text is analyzed in overlapping windows instead of being rejected.
/// </summary>
/// <remarks>
/// <para>
/// Azure AI Language refuses a synchronous-call document over 5,120 text elements with a
/// per-document error, so longer text is analyzed in windows. Text that fits is passed through
/// unchanged in a single call. Longer text is split at whitespace where possible into windows that
/// overlap, so an entity that straddles a boundary lies whole inside one of them; each window is
/// analyzed on its own, one call at a time, and the spans are mapped back onto the full text. The
/// overlaps are then deduplicated: the same span from two windows is reported once, and a span one
/// window saw only partially (the boundary cut through it) gives way to the same-type span another
/// window saw whole.
/// </para>
/// <para>
/// Each window is a separate call to the inner recognizer, subject to its own timeout and failure
/// handling: with a fail-open inner recognizer a failed window contributes nothing and the other
/// windows still count. Whitespace-only windows are not analyzed. The wrapper takes on the inner
/// recognizer's entities, language, name and context words, but not its lifetime - whoever owns the
/// inner recognizer still disposes it.
/// </para>
/// </remarks>
internal sealed class ChunkingEntityRecognizer : EntityRecognizer
{
    private readonly EntityRecognizer _inner;
    private readonly int _maxChunkLength;
    private readonly int _chunkOverlap;

    /// <summary>Initializes a new instance of the <see cref="ChunkingEntityRecognizer"/> class.</summary>
    /// <param name="inner">The recognizer to call once per window.</param>
    /// <param name="maxChunkLength">The largest window, in UTF-16 code units, the inner recognizer is given.</param>
    /// <param name="chunkOverlap">The minimum overlap, in UTF-16 code units, between consecutive windows.</param>
    public ChunkingEntityRecognizer(EntityRecognizer inner, int maxChunkLength, int chunkOverlap)
        : base(
            (inner ?? throw new ArgumentNullException(nameof(inner))).SupportedEntities,
            name: inner.Name,
            supportedLanguage: inner.SupportedLanguage,
            context: inner.Context,
            countryCode: inner.CountryCode)
    {
        // fail on a bad window configuration here rather than on the first long text
        TextChunker.ValidateWindowSize(maxChunkLength, chunkOverlap);

        _inner = inner;
        _maxChunkLength = maxChunkLength;
        _chunkOverlap = chunkOverlap;
    }

    /// <inheritdoc />
    public override bool RequiresAsync => _inner.RequiresAsync;

    /// <inheritdoc />
    public override IReadOnlyList<RecognizerResult> Analyze(string text, IReadOnlyList<string> entities)
    {
        var windows = TextChunker.Split(text, _maxChunkLength, _chunkOverlap);
        if (windows.Count == 1)
            return _inner.Analyze(text, entities);

        var found = new List<WindowResult>();
        for (var index = 0; index < windows.Count; index++)
        {
            var window = windows[index];
            if (text.AsSpan(window.Start, window.Length).IsWhiteSpace())
                continue;

            var results = _inner.Analyze(text.Substring(window.Start, window.Length), entities);
            Collect(found, index, window, results);
        }

        return Merge(found);
    }

    /// <inheritdoc />
    /// <remarks>
    /// Cancellation of <paramref name="ct"/> throws <see cref="OperationCanceledException"/> even when a
    /// fail-open inner recognizer answers the request it tore down with no entities, so a canceled
    /// analysis never comes back as a partial result.
    /// </remarks>
    public override async ValueTask<IReadOnlyList<RecognizerResult>> AnalyzeAsync(
        string text, IReadOnlyList<string> entities, CancellationToken ct = default)
    {
        var windows = TextChunker.Split(text, _maxChunkLength, _chunkOverlap);
        if (windows.Count == 1)
        {
            var single = await _inner.AnalyzeAsync(text, entities, ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested();
            return single;
        }

        // one window at a time: a burst of parallel calls is what trips a service's rate limit, and
        // a throttled window would be lost to fail-open
        var found = new List<WindowResult>();
        for (var index = 0; index < windows.Count; index++)
        {
            var window = windows[index];
            if (text.AsSpan(window.Start, window.Length).IsWhiteSpace())
                continue;

            var results = await _inner.AnalyzeAsync(text.Substring(window.Start, window.Length), entities, ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested();
            Collect(found, index, window, results);
        }

        return Merge(found);
    }

    // maps each result from window coordinates back onto the full text
    private static void Collect(List<WindowResult> found, int windowIndex, TextWindow window, IReadOnlyList<RecognizerResult> results)
    {
        foreach (var result in results)
        {
            var mapped = new RecognizerResult(
                result.EntityType,
                result.Start + window.Start,
                result.End + window.Start,
                result.Score,
                result.RecognitionMetadata,
                result.AnalysisExplanation);

            found.Add(new WindowResult(windowIndex, mapped));
        }
    }

    private static List<RecognizerResult> Merge(List<WindowResult> found)
    {
        // the same span seen by two overlapping windows: keep one, with the higher score
        var unique = new List<WindowResult>(found.Count);
        foreach (var candidate in found)
        {
            var existing = unique.FindIndex(u =>
                u.Result.EntityType == candidate.Result.EntityType && u.Result.EqualIndices(candidate.Result));

            if (existing < 0)
                unique.Add(candidate);
            else if (candidate.Result.Score > unique[existing].Result.Score)
                unique[existing] = candidate;
        }

        // a span one window saw only partially gives way to the same-type span another window saw
        // whole; spans nested within a single window's answer are left as the recognizer reported them
        return unique
            .Where(u => !unique.Exists(other =>
                other.WindowIndex != u.WindowIndex &&
                other.Result.EntityType == u.Result.EntityType &&
                !other.Result.EqualIndices(u.Result) &&
                u.Result.ContainedIn(other.Result)))
            .Select(u => u.Result)
            .ToList();
    }

    private readonly record struct WindowResult(int WindowIndex, RecognizerResult Result);
}
