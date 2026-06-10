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

    internal DefenderModelSession(string modelPath, string vocabPath, int maxTokenLength, float temperatureT)
    {
        _session = new InferenceSession(modelPath);
        _tokenizer = BertTokenizer.Create(vocabPath, new BertOptions { LowerCaseBeforeTokenization = true });
        _maxTokenLength = maxTokenLength;
        _temperatureT = temperatureT;
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
        _session.Dispose();
    }
}
