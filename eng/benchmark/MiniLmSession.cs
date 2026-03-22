using Microsoft.ML.OnnxRuntime;
using Microsoft.ML.OnnxRuntime.Tensors;
using Microsoft.ML.Tokenizers;

namespace Benchmark;

/// <summary>
/// ONNX inference wrapper for the StackOneHQ/defender fine-tuned MiniLM-L6-v2 model.
/// Architecture: BERT WordPiece tokenizer → ONNX (fine-tuned MiniLM) → single logit → sigmoid → injection score.
/// Model: ~22MB quantized int8, 6 layers, 384 hidden, max 256 tokens.
/// </summary>
internal sealed class MiniLmSession : IDisposable
{
    private readonly InferenceSession _session;
    private readonly BertTokenizer _tokenizer;
    private readonly int _maxTokenLength;

    internal MiniLmSession(string modelPath, string vocabPath, int maxTokenLength = 256)
    {
        _session = new InferenceSession(modelPath);
        _tokenizer = BertTokenizer.Create(vocabPath, new BertOptions { LowerCaseBeforeTokenization = true });
        _maxTokenLength = maxTokenLength;
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
        var tokenTypeIds = new long[seqLen];

        for (var i = 0; i < seqLen; i++)
        {
            inputIds[i] = encoded[i];
            attentionMask[i] = 1;
        }

        var inputIdsTensor = new DenseTensor<long>(inputIds, [1, seqLen]);
        var attentionMaskTensor = new DenseTensor<long>(attentionMask, [1, seqLen]);
        var tokenTypeIdsTensor = new DenseTensor<long>(tokenTypeIds, [1, seqLen]);

        var inputs = new List<NamedOnnxValue>();
        foreach (var name in _session.InputMetadata.Keys)
        {
            var tensor = name switch
            {
                "input_ids" => inputIdsTensor,
                "attention_mask" => attentionMaskTensor,
                "token_type_ids" => tokenTypeIdsTensor,
                _ => inputIdsTensor
            };
            inputs.Add(NamedOnnxValue.CreateFromTensor(name, tensor));
        }

        using var results = _session.Run(inputs);

        // Defender model: single logit output → sigmoid
        var logits = results[0].AsEnumerable<float>().ToArray();
        var logit = logits[0];
        return Sigmoid(logit);
    }

    private static float Sigmoid(float x) => 1.0f / (1.0f + MathF.Exp(-x));

    public void Dispose()
    {
        _session.Dispose();
    }
}
