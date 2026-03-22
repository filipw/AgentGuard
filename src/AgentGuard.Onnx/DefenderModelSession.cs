using Microsoft.ML.OnnxRuntime;
using Microsoft.ML.OnnxRuntime.Tensors;
using Microsoft.ML.Tokenizers;

namespace AgentGuard.Onnx;

/// <summary>
/// ONNX inference wrapper for the StackOne Defender fine-tuned MiniLM-L6-v2 model.
/// Architecture: BERT WordPiece tokenizer → ONNX inference → single logit → sigmoid → injection score.
/// Thread-safe: InferenceSession.Run() supports concurrent calls.
/// </summary>
/// <remarks>
/// Based on the StackOne Defender project (https://github.com/StackOneHQ/defender), Apache 2.0 license.
/// The model is a fine-tuned all-MiniLM-L6-v2 (~22 MB int8 quantized) trained for prompt injection detection.
/// </remarks>
internal sealed class DefenderModelSession : IDisposable
{
    private readonly InferenceSession _session;
    private readonly BertTokenizer _tokenizer;
    private readonly int _maxTokenLength;

    internal DefenderModelSession(string modelPath, string vocabPath, int maxTokenLength)
    {
        _session = new InferenceSession(modelPath);
        _tokenizer = BertTokenizer.Create(vocabPath, new BertOptions { LowerCaseBeforeTokenization = true });
        _maxTokenLength = maxTokenLength;
    }

    /// <summary>
    /// Returns the injection probability (0.0 = safe, 1.0 = injection).
    /// </summary>
    internal float Classify(string text)
    {
        var encoded = _tokenizer.EncodeToIds(text, _maxTokenLength, out _, out _);
        var seqLen = encoded.Count;

        var inputIds = new long[seqLen];
        var attentionMask = new long[seqLen];
        var tokenTypeIds = new long[seqLen];

        for (var i = 0; i < seqLen; i++)
        {
            inputIds[i] = encoded[i];
            attentionMask[i] = 1;
        }

        var inputIdsTensor = new DenseTensor<long>(inputIds, [1, seqLen]);
        var attentionMaskTensor = new DenseTensor<long>(attentionMask, [1, seqLen]);
        var tokenTypeIdsTensor = new DenseTensor<long>(tokenTypeIds, [1, seqLen]);

        var inputs = CreateNamedInputs(inputIdsTensor, attentionMaskTensor, tokenTypeIdsTensor);

        using var results = _session.Run(inputs);

        // Defender model outputs a single logit → sigmoid for injection probability
        var logits = results[0].AsEnumerable<float>().ToArray();
        return Sigmoid(logits[0]);
    }

    private List<NamedOnnxValue> CreateNamedInputs(
        DenseTensor<long> inputIds,
        DenseTensor<long> attentionMask,
        DenseTensor<long> tokenTypeIds)
    {
        var inputs = new List<NamedOnnxValue>(_session.InputMetadata.Count);

        foreach (var name in _session.InputMetadata.Keys)
        {
            var tensor = name switch
            {
                "input_ids" => inputIds,
                "attention_mask" => attentionMask,
                "token_type_ids" => tokenTypeIds,
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
