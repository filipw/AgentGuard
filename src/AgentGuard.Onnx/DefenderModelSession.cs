using Microsoft.ML.OnnxRuntime;
using Microsoft.ML.OnnxRuntime.Tensors;
using Microsoft.ML.Tokenizers;

namespace AgentGuard.Onnx;

/// <summary>
/// Inference result from the Defender multi-head classifier.
/// Both scores are temperature-calibrated probabilities in [0, 1].
/// </summary>
/// <param name="Main">Main-head injection probability. Higher = more likely injection.</param>
/// <param name="Aux">
/// Auxiliary-head probability that the directive targets a human reader.
/// A high aux score vetoes a block: imperative-but-benign content (e.g. "show me my orders")
/// scores high on the main head but also high on aux, so the veto rescues it.
/// </param>
internal readonly record struct DefenderScore(float Main, float Aux);

/// <summary>
/// ONNX inference wrapper for the StackOne Defender multi-head MiniLM-L6 model (minilm-multihead-v5).
/// Architecture: BERT WordPiece tokenizer → ONNX inference (mean pooling + dual head baked into graph)
/// → two logits [main, aux] → temperature scaling → sigmoid → calibrated scores.
/// Thread-safe: InferenceSession.Run() supports concurrent calls.
/// <para>
/// Sessions are shared process-wide via a reference-counted cache keyed by model files and
/// calibration. Multiple rules pointing at the same model (e.g. several gated Defender rules at
/// different thresholds) reuse one <see cref="InferenceSession"/>
/// </para>
/// </summary>
/// <remarks>
/// Based on the StackOne Defender project (https://github.com/StackOneHQ/defender), Apache 2.0 license.
/// The model is a fine-tuned all-MiniLM-L6-v2 (~22 MB int8 quantized) with a dual classification head:
/// a main injection head and an auxiliary "directed at human reader" head used for the veto rule.
/// </remarks>
internal sealed class DefenderModelSession : IDisposable
{
    private readonly InferenceSession _session;
    private readonly BertTokenizer _tokenizer;
    private readonly int _maxTokenLength;
    private readonly float _temperatureT;
    private readonly SessionKey? _cacheKey;

    private readonly record struct SessionKey(string ModelPath, string VocabPath, int MaxTokenLength, float TemperatureT);

    private sealed class CacheEntry
    {
        public required DefenderModelSession Session { get; init; }
        public int RefCount { get; set; }
    }

    private static readonly Dictionary<SessionKey, CacheEntry> _cache = [];
    private static readonly object _cacheLock = new();

    private DefenderModelSession(string modelPath, string vocabPath, int maxTokenLength, float temperatureT, SessionKey? cacheKey)
    {
        _session = new InferenceSession(modelPath);
        _tokenizer = BertTokenizer.Create(vocabPath, new BertOptions { LowerCaseBeforeTokenization = true });
        _maxTokenLength = maxTokenLength;
        _temperatureT = temperatureT;
        _cacheKey = cacheKey;
    }

    /// <summary>
    /// Returns a process-wide shared session for the given model, loading it on first use and
    /// reusing it for subsequent callers. Reference-counted: balance each <see cref="Acquire"/>
    /// with a <see cref="Dispose"/>; the underlying ONNX session is freed when the count reaches zero.
    /// </summary>
    internal static DefenderModelSession Acquire(string modelPath, string vocabPath, int maxTokenLength, float temperatureT)
    {
        var key = new SessionKey(modelPath, vocabPath, maxTokenLength, temperatureT);
        lock (_cacheLock)
        {
            if (_cache.TryGetValue(key, out var entry))
            {
                entry.RefCount++;
                return entry.Session;
            }

            var session = new DefenderModelSession(modelPath, vocabPath, maxTokenLength, temperatureT, key);
            _cache[key] = new CacheEntry { Session = session, RefCount = 1 };
            return session;
        }
    }

    /// <summary>Number of distinct loaded sessions currently cached. For tests/diagnostics.</summary>
    internal static int ActiveSessionCount
    {
        get { lock (_cacheLock) { return _cache.Count; } }
    }

    /// <summary>
    /// Classifies the text and returns the temperature-calibrated main and aux scores.
    /// </summary>
    internal DefenderScore Classify(string text)
    {
        var encoded = _tokenizer.EncodeToIds(text, _maxTokenLength, out _, out _);
        var seqLen = encoded.Count;

        var inputIds = new long[seqLen];
        var attentionMask = new long[seqLen];

        for (var i = 0; i < seqLen; i++)
        {
            inputIds[i] = encoded[i];
            attentionMask[i] = 1;
        }

        var inputIdsTensor = new DenseTensor<long>(inputIds, [1, seqLen]);
        var attentionMaskTensor = new DenseTensor<long>(attentionMask, [1, seqLen]);

        var inputs = CreateNamedInputs(inputIdsTensor, attentionMaskTensor);

        using var results = _session.Run(inputs);

        // the multi-head model outputs two logits [main, aux] (tensor shape [1, 2]).
        // each is divided by the calibration temperature before sigmoid.
        var logits = results[0].AsEnumerable<float>().ToArray();

        if (logits.Length < 2)
        {
            throw new InvalidOperationException(
                $"Defender multi-head model expected 2 output logits but got {logits.Length}. " +
                "Ensure the bundled minilm-multihead-v5 model is being used.");
        }

        var main = Sigmoid(logits[0] / _temperatureT);
        var aux = Sigmoid(logits[1] / _temperatureT);
        return new DefenderScore(main, aux);
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

    /// <summary>
    /// Sigmoid activation: maps logit to [0, 1] probability.
    /// </summary>
    internal static float Sigmoid(float x) => 1.0f / (1.0f + MathF.Exp(-x));

    public void Dispose()
    {
        if (_cacheKey is not { } key)
        {
            // not from the shared cache (e.g. a directly-constructed instance) — dispose directly
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
}
