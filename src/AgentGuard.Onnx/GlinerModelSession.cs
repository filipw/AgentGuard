using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.ML.OnnxRuntime;
using Microsoft.ML.OnnxRuntime.Tensors;
using Microsoft.ML.Tokenizers;

namespace AgentGuard.Onnx;

/// <summary>A named-entity span over the original text: char offsets, model label, and sigmoid score.</summary>
/// <param name="CharStart">Start offset (inclusive) in the original text.</param>
/// <param name="CharEnd">End offset (exclusive) in the original text.</param>
/// <param name="Label">The model prompt label (lowercase, e.g. <c>person</c>).</param>
/// <param name="Score">Sigmoid probability in [0, 1].</param>
internal readonly record struct NerSpan(int CharStart, int CharEnd, string Label, float Score);

/// <summary>
/// ONNX inference wrapper for a zero-shot GLiNER-style span NER model (mDeBERTa-v3 backbone).
/// Unlike the frozen-taxonomy content-safety classifier, the entity labels are part of the runtime
/// input: each call assembles
/// <c>[CLS] (&lt;&lt;ENT&gt;&gt; label-subwords)xN &lt;&lt;SEP&gt;&gt; word-subwords... [SEP]</c>, with a
/// <c>words_mask</c> marking the first subword of each text word, enumerates every word span up to
/// <c>max_width</c>, scores each against every label, and decodes via sigmoid -> threshold -> flat
/// greedy non-overlap. Span word indices are mapped back to character offsets.
/// Thread-safe: <see cref="InferenceSession.Run(IReadOnlyCollection{NamedOnnxValue})"/> supports concurrent calls.
/// <para>
/// Sessions are shared process-wide via a reference-counted cache keyed by the model/tokenizer/config
/// files and the length/width caps, so multiple recognizers on the same model reuse one
/// <see cref="InferenceSession"/>.
/// </para>
/// </summary>
internal sealed class GlinerModelSession : IRefCountedSession
{
    // gliner words_splitter_type "whitespace": runs of word chars (allowing internal -/_) or any
    // single non-space char. Unicode-aware \w matches accented letters and CJK ideographs.
    private static readonly Regex _wordSplitter = new(@"\w+(?:[-_]\w+)*|\S",
        RegexOptions.Compiled | RegexOptions.CultureInvariant, TimeSpan.FromSeconds(2));

    private readonly InferenceSession _session;
    private readonly SentencePieceTokenizer _tokenizer;
    private readonly int _maxTokenLength;
    private readonly int _maxSpanWidth;
    private readonly int _maxChunkChars;
    private readonly GlinerConfig _config;
    private readonly SessionKey? _cacheKey;

    private readonly record struct SessionKey(string ModelPath, string TokenizerPath, string ConfigPath, int MaxTokenLength, int MaxSpanWidth, int MaxChunkChars);

    private static readonly RefCountedSessionPool<SessionKey, GlinerModelSession> _pool = new();

    private GlinerModelSession(string modelPath, string tokenizerPath, string configPath, int maxTokenLength, int maxSpanWidth, int maxChunkChars, SessionKey? cacheKey)
    {
        _session = OnnxSessionFactory.Create(modelPath);

        using (var tokenizerStream = File.OpenRead(tokenizerPath))
        {
            // content ids only - we insert [CLS]/[SEP]/<<ENT>>/<<SEP>> ids manually, matching the
            // HF is_split_into_words assembly (each word spm-encoded with its own ▁ dummy prefix).
            _tokenizer = SentencePieceTokenizer.Create(
                tokenizerStream, addBeginningOfSentence: false, addEndOfSentence: false);
        }

        _config = GlinerConfig.Load(configPath);
        _maxTokenLength = maxTokenLength;
        _maxSpanWidth = maxSpanWidth;
        _maxChunkChars = maxChunkChars;
        _cacheKey = cacheKey;
    }

    /// <summary>
    /// Returns a process-wide shared session for the given model, loading it on first use. Reference
    /// counted: balance each <see cref="Acquire"/> with a <see cref="Dispose"/>.
    /// </summary>
    internal static GlinerModelSession Acquire(string modelPath, string tokenizerPath, string configPath, int maxTokenLength, int maxSpanWidth, int maxChunkChars)
    {
        var key = new SessionKey(modelPath, tokenizerPath, configPath, maxTokenLength, maxSpanWidth, maxChunkChars);
        return _pool.Acquire(key, () => new GlinerModelSession(modelPath, tokenizerPath, configPath, maxTokenLength, maxSpanWidth, maxChunkChars, key));
    }

    /// <summary>Number of distinct loaded sessions currently cached. For tests/diagnostics.</summary>
    internal static int ActiveSessionCount => _pool.ActiveCount;

    /// <summary>The model's maximum span width (number of words). Exposed for diagnostics.</summary>
    internal int MaxSpanWidth => Math.Min(_maxSpanWidth, _config.MaxWidth);

    /// <summary>
    /// Detects entity spans for the given labels and returns those scoring at or above
    /// <paramref name="threshold"/>, decoded flat (no overlaps), mapped to character offsets.
    /// </summary>
    internal IReadOnlyList<NerSpan> Predict(string text, IReadOnlyList<string> labels, float threshold)
    {
        if (string.IsNullOrEmpty(text) || labels.Count == 0)
            return [];

        var words = SplitWords(text);
        if (words.Count == 0)
            return [];

        var maxWidth = MaxSpanWidth;

        // encode the (stable) labels once and compute the exact prompt token cost:
        // [CLS] + sum over labels(<<ENT>> + label-subwords) + <<SEP>>. labelSubwords feeds both the
        // chunk budget and the per-chunk input assembly, so labels are never re-tokenized per chunk.
        var labelSubwords = new long[labels.Count][];
        var promptTokens = 2; // [CLS] and the trailing <<SEP>> that closes the prompt
        for (var i = 0; i < labels.Count; i++)
        {
            labelSubwords[i] = EncodeWord(labels[i]);
            promptTokens += 1 + labelSubwords[i].Length; // <<ENT>> + the label's subwords
        }

        // decode each chunk independently and merge: chunks are word- and char-disjoint, so a span in
        // one chunk can never overlap a span in another. Decoding the accumulated candidates in one
        // pass would instead compare chunk-LOCAL word indices and spuriously drop colliding spans.
        var selected = new List<SpanCandidate>();
        var chunkCandidates = new List<SpanCandidate>();
        foreach (var chunk in ChunkWords(words, promptTokens))
        {
            chunkCandidates.Clear();
            ScoreChunk(chunk, labels, labelSubwords, threshold, maxWidth, chunkCandidates);
            selected.AddRange(GreedyFlatDecode(chunkCandidates));
        }

        // greedy decode returns each chunk sorted by its local word index; order the merged set by
        // global char offset for a stable left-to-right result.
        selected.Sort((a, b) => a.CharStart.CompareTo(b.CharStart));

        var spans = new List<NerSpan>(selected.Count);
        foreach (var c in selected)
            spans.Add(new NerSpan(c.CharStart, c.CharEnd, c.Label, c.Score));

        return spans;
    }

    private void ScoreChunk(List<Word> words, IReadOnlyList<string> labels, long[][] labelSubwords, float threshold, int maxWidth, List<SpanCandidate> sink)
    {
        var numWords = words.Count;
        var numClasses = labels.Count;

        var (inputIds, wordsMask) = AssembleInput(words, labelSubwords);
        var seqLen = inputIds.Length;

        // span_idx: for start in [0,numWords), w in [0,maxWidth): (start, start+w). num_spans = numWords*maxWidth
        var numSpans = numWords * maxWidth;
        var spanIdx = new long[numSpans * 2];
        var spanMask = new bool[numSpans];
        for (var start = 0; start < numWords; start++)
        {
            for (var w = 0; w < maxWidth; w++)
            {
                var flat = start * maxWidth + w;
                var end = start + w;
                spanIdx[flat * 2] = start;
                spanIdx[flat * 2 + 1] = end;
                spanMask[flat] = end < numWords;
            }
        }

        var attentionMask = new long[seqLen];
        Array.Fill(attentionMask, 1L);

        var inputs = new List<NamedOnnxValue>(_session.InputMetadata.Count);
        foreach (var name in _session.InputMetadata.Keys)
        {
            NamedOnnxValue value = name switch
            {
                "attention_mask" => NamedOnnxValue.CreateFromTensor(name, new DenseTensor<long>(attentionMask, [1, seqLen])),
                "words_mask" => NamedOnnxValue.CreateFromTensor(name, new DenseTensor<long>(wordsMask, [1, seqLen])),
                "text_lengths" => NamedOnnxValue.CreateFromTensor(name, new DenseTensor<long>(new long[] { numWords }, [1, 1])),
                "span_idx" => NamedOnnxValue.CreateFromTensor(name, new DenseTensor<long>(spanIdx, [1, numSpans, 2])),
                "span_mask" => NamedOnnxValue.CreateFromTensor(name, new DenseTensor<bool>(spanMask, [1, numSpans])),
                _ => NamedOnnxValue.CreateFromTensor(name, new DenseTensor<long>(inputIds, [1, seqLen])),
            };
            inputs.Add(value);
        }

        using var results = _session.Run(inputs);
        var logits = results[0].AsEnumerable<float>().ToArray(); // [1, numWords(L), maxWidth(K), numClasses(C)]

        EnumerateCandidates(logits, words, labels, numWords, maxWidth, numClasses, threshold, sink);
    }

    // assemble [CLS] (<<ENT>> label-subwords)xN <<SEP>> word-subwords... [SEP] + the aligned words_mask
    private (long[] InputIds, long[] WordsMask) AssembleInput(List<Word> words, long[][] labelSubwords)
    {
        var ids = new List<long>(64) { _config.ClsId };
        var mask = new List<long>(64) { 0 };

        foreach (var label in labelSubwords)
        {
            ids.Add(_config.EntTokenId);
            mask.Add(0);
            foreach (var sub in label)
            {
                ids.Add(sub);
                mask.Add(0);
            }
        }

        ids.Add(_config.SepTokenId);
        mask.Add(0);

        for (var wi = 0; wi < words.Count; wi++)
        {
            var sub = words[wi].SubwordIds;
            for (var j = 0; j < sub.Length; j++)
            {
                ids.Add(sub[j]);
                mask.Add(j == 0 ? wi + 1 : 0);
            }
        }

        ids.Add(_config.SepId);
        mask.Add(0);

        return (ids.ToArray(), mask.ToArray());
    }

    // enumerate (start, width, class) candidates above threshold and valid (start+width < numWords)
    internal static void EnumerateCandidates(
        float[] logits,
        IReadOnlyList<Word> words,
        IReadOnlyList<string> labels,
        int numWords,
        int maxWidth,
        int numClasses,
        float threshold,
        List<SpanCandidate> sink)
    {
        // logits laid out as [L, K, C] row-major (batch dim 1 dropped)
        for (var start = 0; start < numWords; start++)
        {
            for (var w = 0; w < maxWidth; w++)
            {
                var end = start + w;
                if (end >= numWords)
                    continue;

                var baseIdx = (start * maxWidth + w) * numClasses;
                for (var c = 0; c < numClasses; c++)
                {
                    var prob = Sigmoid(logits[baseIdx + c]);
                    if (prob >= threshold)
                    {
                        sink.Add(new SpanCandidate(
                            start, end,
                            words[start].CharStart, words[end].CharEnd,
                            labels[c], prob));
                    }
                }
            }
        }
    }

    // flat greedy: sort by score desc, accept a span only if it does not overlap an accepted one
    // (inclusive word ranges; equal ranges overlap). Returns spans sorted by start word index.
    internal static List<SpanCandidate> GreedyFlatDecode(List<SpanCandidate> candidates)
    {
        var sorted = candidates.OrderByDescending(c => c.Score).ToList();
        var selected = new List<SpanCandidate>();

        foreach (var span in sorted)
        {
            var overlaps = false;
            foreach (var existing in selected)
            {
                if (Overlaps(span, existing))
                {
                    overlaps = true;
                    break;
                }
            }

            if (!overlaps)
                selected.Add(span);
        }

        selected.Sort((a, b) => a.WordStart.CompareTo(b.WordStart));
        return selected;
    }

    // mirrors gliner has_overlapping: same (start,end) overlaps; otherwise overlap unless disjoint
    private static bool Overlaps(SpanCandidate a, SpanCandidate b)
    {
        if (a.WordStart == b.WordStart && a.WordEnd == b.WordEnd)
            return true;

        return !(a.WordStart > b.WordEnd || b.WordStart > a.WordEnd);
    }

    private List<Word> SplitWords(string text)
    {
        var words = new List<Word>();
        foreach (Match m in _wordSplitter.Matches(text))
        {
            var subwords = EncodeWord(m.Value);
            if (subwords.Length == 0)
                continue;
            words.Add(new Word(m.Index, m.Index + m.Length, subwords));
        }

        return words;
    }

    // pack words into chunks that fit the token budget (prompt + words + trailing [SEP]) and the char
    // cap. chunks never split a word; spans carry global char offsets so merging is trivial.
    // <paramref name="promptTokens"/> is the exact label-prefix cost ([CLS] + per-label <<ENT>> +
    // label subwords + <<SEP>>), so the assembled sequence is guaranteed to fit MaxTokenLength.
    private IEnumerable<List<Word>> ChunkWords(IReadOnlyList<Word> words, int promptTokens)
    {
        // reserve the prompt prefix and the trailing [SEP]; the rest is the per-chunk word budget.
        var budget = Math.Max(8, _maxTokenLength - promptTokens - 1);

        var chunk = new List<Word>();
        var tokenCount = 0;
        var charCount = 0;

        foreach (var original in words)
        {
            var word = original;
            var wordTokens = word.SubwordIds.Length;

            // a single word longer than the whole budget (e.g. a giant unbroken token) would blow the
            // sequence past MaxTokenLength; truncate its subwords so the assembled input always fits.
            if (wordTokens > budget)
            {
                var truncated = new long[budget];
                Array.Copy(word.SubwordIds, truncated, budget);
                word = word with { SubwordIds = truncated };
                wordTokens = budget;
            }

            var wordChars = word.CharEnd - word.CharStart;
            if (chunk.Count > 0 && (tokenCount + wordTokens > budget || charCount + wordChars > _maxChunkChars))
            {
                yield return chunk;
                chunk = [];
                tokenCount = 0;
                charCount = 0;
            }

            chunk.Add(word);
            tokenCount += wordTokens;
            charCount += wordChars;
        }

        if (chunk.Count > 0)
            yield return chunk;
    }

    private long[] EncodeWord(string word)
    {
        var ids = _tokenizer.EncodeToIds(word);
        if (ids.Count == 0)
            return [];

        var result = new long[ids.Count];
        for (var i = 0; i < ids.Count; i++)
            result[i] = ids[i];
        return result;
    }

    /// <summary>Sigmoid activation: maps a logit to a [0, 1] probability.</summary>
    internal static float Sigmoid(float x) => 1.0f / (1.0f + MathF.Exp(-x));

    /// <summary>Releases this holder's reference; the pool frees the session at zero.</summary>
    public void Dispose()
    {
        if (_cacheKey is not { } key)
        {
            _session.Dispose();
            return;
        }

        _pool.Release(key);
    }

    void IRefCountedSession.ReleaseResources() => _session.Dispose();

    /// <summary>A text word with its char span and precomputed subword ids.</summary>
    internal readonly record struct Word(int CharStart, int CharEnd, long[] SubwordIds);

    /// <summary>A candidate span during decoding: word indices, char offsets, label and score.</summary>
    internal readonly record struct SpanCandidate(int WordStart, int WordEnd, int CharStart, int CharEnd, string Label, float Score);

    /// <summary>The C#-facing model config (special-token ids + max span width) shipped as config.json.</summary>
    private sealed record GlinerConfig(long ClsId, long SepId, long PadId, long EntTokenId, long SepTokenId, int MaxWidth)
    {
        public static GlinerConfig Load(string configPath)
        {
            using var stream = File.OpenRead(configPath);
            using var doc = JsonDocument.Parse(stream);
            var root = doc.RootElement;

            long Get(string name) => root.GetProperty(name).GetInt64();

            var maxWidth = root.TryGetProperty("max_width", out var mw) ? mw.GetInt32() : 12;
            if (maxWidth <= 0)
                throw new InvalidOperationException($"config.json at '{configPath}' has a non-positive max_width.");

            return new GlinerConfig(
                ClsId: Get("cls_id"),
                SepId: Get("sep_id"),
                PadId: Get("pad_id"),
                EntTokenId: Get("ent_token_id"),
                SepTokenId: Get("sep_token_id"),
                MaxWidth: maxWidth);
        }
    }
}
