using System.Text.Json;
using Microsoft.ML.OnnxRuntime;
using Microsoft.ML.OnnxRuntime.Tensors;
using Microsoft.ML.Tokenizers;

namespace AgentGuard.Onnx;

/// <summary>
/// Per-label content-safety score from the Opir-multilang classifier.
/// </summary>
/// <param name="MaxProbability">Highest per-label probability (the binary "is unsafe" signal).</param>
/// <param name="MaxLabel">The harm label that produced <see cref="MaxProbability"/>.</param>
/// <param name="LabelProbabilities">Per-label sigmoid probabilities, aligned with <see cref="OpirModelSession.Labels"/>.</param>
internal readonly record struct OpirScore(float MaxProbability, string MaxLabel, IReadOnlyList<float> LabelProbabilities);

/// <summary>
/// ONNX inference wrapper for the Opir-multilang content-safety classifier
/// (knowledgator/opir-multitask-multilang-v1.0, GLiClass uni-encoder over mDeBERTa-v3-base).
/// The taxonomy is frozen at export time, so the label prefix is a constant token-id sequence
/// (shipped in <c>prefix.json</c>): each input is assembled as
/// <c>prefix_ids ++ spm(text) ++ [SEP]</c>, run through one mDeBERTa-v3 forward, and scored per
/// label. Decision is left to the caller (block iff max sigmoid >= threshold).
/// Thread-safe: <see cref="InferenceSession.Run(IReadOnlyCollection{NamedOnnxValue})"/> supports concurrent calls.
/// <para>
/// Sessions are shared process-wide via a reference-counted cache keyed by the model/tokenizer/prefix
/// files and max length, so multiple rules on the same model (e.g. gated rules at different
/// thresholds) reuse one <see cref="InferenceSession"/>.
/// </para>
/// </summary>
internal sealed class OpirModelSession : IDisposable
{
    private readonly InferenceSession _session;
    private readonly SentencePieceTokenizer _tokenizer;
    private readonly int _maxTokenLength;
    private readonly long[] _prefixIds;
    private readonly long _sepId;
    private readonly string[] _unsafeLabels;
    private readonly int[] _unsafeIndices;
    private readonly int _logitCount;
    private readonly SessionKey? _cacheKey;

    private readonly record struct SessionKey(string ModelPath, string TokenizerPath, string PrefixPath, int MaxTokenLength);

    private sealed class CacheEntry
    {
        public required OpirModelSession Session { get; init; }
        public int RefCount { get; set; }
    }

    private static readonly Dictionary<SessionKey, CacheEntry> _cache = [];
    private static readonly object _cacheLock = new();

    private OpirModelSession(string modelPath, string tokenizerPath, string prefixPath, int maxTokenLength, SessionKey? cacheKey)
    {
        _session = new InferenceSession(modelPath);

        using (var tokenizerStream = File.OpenRead(tokenizerPath))
        {
            // content ids only - the frozen prefix supplies [CLS] and we append [SEP] ourselves.
            // the default Create() would prepend a BOS token (id 1 == [CLS]), doubling it.
            _tokenizer = SentencePieceTokenizer.Create(
                tokenizerStream, addBeginningOfSentence: false, addEndOfSentence: false);
        }

        var prefix = OpirPrefix.Load(prefixPath);
        _prefixIds = prefix.PrefixIds;
        _sepId = prefix.SepId;
        _logitCount = prefix.Labels.Length;

        // the block decision is over the harm categories only; the "safe and benign" sentinel that
        // GLiClass needs for calibration is baked into the graph but excluded here.
        _unsafeLabels = prefix.UnsafeLabels;
        _unsafeIndices = new int[_unsafeLabels.Length];
        for (var i = 0; i < _unsafeLabels.Length; i++)
        {
            var idx = Array.IndexOf(prefix.Labels, _unsafeLabels[i]);
            if (idx < 0)
                throw new InvalidOperationException(
                    $"prefix.json unsafe label '{_unsafeLabels[i]}' is not present in the labels array.");
            _unsafeIndices[i] = idx;
        }

        _maxTokenLength = maxTokenLength;
        _cacheKey = cacheKey;
    }

    /// <summary>
    /// Returns a process-wide shared session for the given model, loading it on first use and
    /// reusing it for subsequent callers. Reference-counted: balance each <see cref="Acquire"/>
    /// with a <see cref="Dispose"/>; the underlying ONNX session is freed when the count reaches zero.
    /// </summary>
    internal static OpirModelSession Acquire(string modelPath, string tokenizerPath, string prefixPath, int maxTokenLength)
    {
        var key = new SessionKey(modelPath, tokenizerPath, prefixPath, maxTokenLength);
        lock (_cacheLock)
        {
            if (_cache.TryGetValue(key, out var entry))
            {
                entry.RefCount++;
                return entry.Session;
            }

            var session = new OpirModelSession(modelPath, tokenizerPath, prefixPath, maxTokenLength, key);
            _cache[key] = new CacheEntry { Session = session, RefCount = 1 };
            return session;
        }
    }

    /// <summary>Number of distinct loaded sessions currently cached. For tests/diagnostics.</summary>
    internal static int ActiveSessionCount
    {
        get { lock (_cacheLock) { return _cache.Count; } }
    }

    /// <summary>The harm categories the block decision is thresholded over (excludes the safe sentinel).</summary>
    internal IReadOnlyList<string> Labels => _unsafeLabels;

    /// <summary>
    /// Scores the text against the harm taxonomy and returns the per-harm-label probabilities plus
    /// the strongest (label, probability) pair. The "safe and benign" calibration label is excluded.
    /// </summary>
    internal OpirScore Classify(string text)
    {
        var (inputIds, attentionMask) = Tokenize(text);

        var inputIdsTensor = new DenseTensor<long>(inputIds, [1, inputIds.Length]);
        var attentionMaskTensor = new DenseTensor<long>(attentionMask, [1, attentionMask.Length]);

        var inputs = CreateNamedInputs(inputIdsTensor, attentionMaskTensor);

        using var results = _session.Run(inputs);
        var logits = results[0].AsEnumerable<float>().ToArray();

        if (logits.Length < _logitCount)
        {
            throw new InvalidOperationException(
                $"Opir model expected {_logitCount} output logits but got {logits.Length}. " +
                "Ensure the frozen-taxonomy opir-multilang model matches prefix.json.");
        }

        var probs = new float[_unsafeLabels.Length];
        var maxProb = float.NegativeInfinity;
        var maxIdx = 0;
        for (var i = 0; i < _unsafeLabels.Length; i++)
        {
            probs[i] = Sigmoid(logits[_unsafeIndices[i]]);
            if (probs[i] > maxProb)
            {
                maxProb = probs[i];
                maxIdx = i;
            }
        }

        return new OpirScore(maxProb, _unsafeLabels[maxIdx], probs);
    }

    private (long[] InputIds, long[] AttentionMask) Tokenize(string text)
    {
        // budget for the variable text: total - frozen prefix - trailing [SEP]
        var textBudget = Math.Max(0, _maxTokenLength - _prefixIds.Length - 1);
        var encoded = _tokenizer.EncodeToIds(text, textBudget, out string? _, out int _);

        var seqLen = _prefixIds.Length + encoded.Count + 1;
        var inputIds = new long[seqLen];
        var attentionMask = new long[seqLen];

        _prefixIds.CopyTo(inputIds, 0);
        for (var i = 0; i < encoded.Count; i++)
            inputIds[_prefixIds.Length + i] = encoded[i];
        inputIds[seqLen - 1] = _sepId;

        Array.Fill(attentionMask, 1L);
        return (inputIds, attentionMask);
    }

    private List<NamedOnnxValue> CreateNamedInputs(
        DenseTensor<long> inputIds,
        DenseTensor<long> attentionMask)
    {
        var inputs = new List<NamedOnnxValue>(_session.InputMetadata.Count);

        foreach (var name in _session.InputMetadata.Keys)
        {
            var tensor = name switch
            {
                "attention_mask" => attentionMask,
                _ => inputIds
            };
            inputs.Add(NamedOnnxValue.CreateFromTensor(name, tensor));
        }

        return inputs;
    }

    /// <summary>Sigmoid activation: maps a logit to a [0, 1] probability.</summary>
    internal static float Sigmoid(float x) => 1.0f / (1.0f + MathF.Exp(-x));

    public void Dispose()
    {
        if (_cacheKey is not { } key)
        {
            _session.Dispose();
            return;
        }

        lock (_cacheLock)
        {
            if (!_cache.TryGetValue(key, out var entry))
                return; // already fully released

            entry.RefCount--;
            if (entry.RefCount <= 0)
            {
                _cache.Remove(key);
                _session.Dispose();
            }
        }
    }

    /// <summary>
    /// The frozen-taxonomy prefix metadata shipped alongside the model (<c>prefix.json</c>): the
    /// precomputed <c>[CLS] &lt;&lt;LABEL&gt;&gt;l1 ... &lt;&lt;SEP&gt;&gt;</c> token-id prefix, the
    /// label set in logit order, and the special-token ids.
    /// </summary>
    private sealed record OpirPrefix(long[] PrefixIds, long SepId, string[] Labels, string[] UnsafeLabels)
    {
        public static OpirPrefix Load(string prefixPath)
        {
            using var stream = File.OpenRead(prefixPath);
            using var doc = JsonDocument.Parse(stream);
            var root = doc.RootElement;

            var prefixIds = root.GetProperty("prefix_ids").EnumerateArray().Select(e => e.GetInt64()).ToArray();
            var labels = root.GetProperty("labels").EnumerateArray().Select(e => e.GetString()!).ToArray();
            var sepId = root.GetProperty("sep_id").GetInt64();

            // unsafe_labels is the harm subset to threshold over; fall back to all labels for older
            // prefix files that predate the safe-sentinel split.
            var unsafeLabels = root.TryGetProperty("unsafe_labels", out var ul)
                ? ul.EnumerateArray().Select(e => e.GetString()!).ToArray()
                : labels;

            if (prefixIds.Length == 0)
                throw new InvalidOperationException($"prefix.json at '{prefixPath}' has an empty prefix_ids array.");
            if (labels.Length == 0)
                throw new InvalidOperationException($"prefix.json at '{prefixPath}' has an empty labels array.");
            if (unsafeLabels.Length == 0)
                throw new InvalidOperationException($"prefix.json at '{prefixPath}' has an empty unsafe_labels array.");

            return new OpirPrefix(prefixIds, sepId, labels, unsafeLabels);
        }
    }
}
