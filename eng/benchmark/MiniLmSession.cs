using Microsoft.ML.OnnxRuntime;
using Microsoft.ML.OnnxRuntime.Tensors;
using Microsoft.ML.Tokenizers;

namespace Benchmark;

/// <summary>
/// ONNX inference wrapper for the StackOneHQ/defender multi-head MiniLM-L6 model (minilm-multihead-v5).
/// Architecture: BERT WordPiece tokenizer → ONNX (mean pooling + dual head) → [main, aux] logits
/// → temperature scaling → sigmoid. Classify returns the calibrated main score; the production rule
/// also applies the aux veto (see AgentGuard.Onnx.DefenderPromptInjectionRule).
/// Model: ~22MB quantized int8, 6 layers, 384 hidden, max 256 tokens.
/// </summary>
internal sealed class MiniLmSession : IDisposable
{
    private readonly InferenceSession _session;
    private readonly BertTokenizer _tokenizer;
    private readonly int _maxTokenLength;
    private readonly float _temperatureT;

    internal MiniLmSession(string modelPath, string vocabPath, int maxTokenLength = 256, float temperatureT = 2.41f)
    {
        _session = new InferenceSession(modelPath);
        _tokenizer = BertTokenizer.Create(vocabPath, new BertOptions { LowerCaseBeforeTokenization = true });
        _maxTokenLength = maxTokenLength;
        _temperatureT = temperatureT;
    }

    /// <summary>
    /// Returns the injection probability (0 = safe, 1 = injection).
    /// </summary>
    internal float Classify(string text)
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

        var inputs = new List<NamedOnnxValue>();
        foreach (var name in _session.InputMetadata.Keys)
        {
            var tensor = name switch
            {
                "attention_mask" => attentionMaskTensor,
                _ => inputIdsTensor
            };
            inputs.Add(NamedOnnxValue.CreateFromTensor(name, tensor));
        }

        using var results = _session.Run(inputs);

        // multi-head model: [main, aux] logits. Classify returns the calibrated main score.
        var logits = results[0].AsEnumerable<float>().ToArray();
        return Sigmoid(logits[0] / _temperatureT);
    }

    private static float Sigmoid(float x) => 1.0f / (1.0f + MathF.Exp(-x));

    public void Dispose()
    {
        _session.Dispose();
    }
}
