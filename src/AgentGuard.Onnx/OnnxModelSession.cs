using Microsoft.ML.OnnxRuntime;
using Microsoft.ML.OnnxRuntime.Tensors;
using Microsoft.ML.Tokenizers;
using Tokenizer = Microsoft.ML.Tokenizers.Tokenizer;

namespace AgentGuard.Onnx;

/// <summary>
/// Internal wrapper around ONNX Runtime inference session for prompt injection classification.
/// Handles tokenization, tensor construction, inference, and softmax.
/// Thread-safe: InferenceSession.Run() supports concurrent calls.
/// </summary>
internal sealed class OnnxModelSession : IDisposable
{
    private readonly InferenceSession _session;
    private readonly Tokenizer _tokenizer;
    private readonly int _maxTokenLength;
    private readonly string[] _inputNames;
    private readonly string[] _outputNames;

    internal OnnxModelSession(string modelPath, Tokenizer tokenizer, int maxTokenLength)
    {
        _session = new InferenceSession(modelPath);
        _tokenizer = tokenizer;
        _maxTokenLength = maxTokenLength;

        _inputNames = _session.InputMetadata.Keys.ToArray();
        _outputNames = _session.OutputMetadata.Keys.ToArray();
    }

    /// <summary>
    /// Classifies the given text and returns (safeProb, injectionProb).
    /// </summary>
    internal (float SafeProbability, float InjectionProbability) Classify(string text)
    {
        var (inputIds, attentionMask) = Tokenize(text);
        var tokenTypeIds = new long[inputIds.Length]; // all zeros for single-segment

        var inputIdsTensor = new DenseTensor<long>(inputIds, [1, inputIds.Length]);
        var attentionMaskTensor = new DenseTensor<long>(attentionMask, [1, attentionMask.Length]);
        var tokenTypeIdsTensor = new DenseTensor<long>(tokenTypeIds, [1, tokenTypeIds.Length]);

        var inputs = CreateNamedInputs(inputIdsTensor, attentionMaskTensor, tokenTypeIdsTensor);

        using var results = _session.Run(inputs);
        var logits = results[0].AsEnumerable<float>().ToArray();

        return Softmax(logits[0], logits[1]);
    }

    private List<NamedOnnxValue> CreateNamedInputs(
        DenseTensor<long> inputIds,
        DenseTensor<long> attentionMask,
        DenseTensor<long> tokenTypeIds)
    {
        var inputs = new List<NamedOnnxValue>(_inputNames.Length);

        foreach (var name in _inputNames)
        {
            var tensor = name switch
            {
                "input_ids" => inputIds,
                "attention_mask" => attentionMask,
                "token_type_ids" => tokenTypeIds,
                _ => inputIds // fallback — some models use different names
            };
            inputs.Add(NamedOnnxValue.CreateFromTensor(name, tensor));
        }

        return inputs;
    }

    private (long[] InputIds, long[] AttentionMask) Tokenize(string text)
    {
        var encoded = _tokenizer.EncodeToIds(text, _maxTokenLength - 2, out string? _, out int _);
        var seqLen = Math.Min(encoded.Count + 2, _maxTokenLength); // +2 for CLS and SEP

        var inputIds = new long[seqLen];
        var attentionMask = new long[seqLen];

        // CLS token (typically id 1 for DeBERTa v3)
        inputIds[0] = 1;
        attentionMask[0] = 1;

        // Copy encoded tokens
        for (var i = 0; i < encoded.Count && i + 1 < seqLen - 1; i++)
        {
            inputIds[i + 1] = encoded[i];
            attentionMask[i + 1] = 1;
        }

        // SEP token (typically id 2 for DeBERTa v3)
        inputIds[seqLen - 1] = 2;
        attentionMask[seqLen - 1] = 1;

        return (inputIds, attentionMask);
    }

    /// <summary>
    /// Computes softmax over two logit values.
    /// </summary>
    internal static (float Safe, float Injection) Softmax(float logit0, float logit1)
    {
        var max = Math.Max(logit0, logit1);
        var exp0 = MathF.Exp(logit0 - max);
        var exp1 = MathF.Exp(logit1 - max);
        var sum = exp0 + exp1;
        return (exp0 / sum, exp1 / sum);
    }

    public void Dispose()
    {
        _session.Dispose();
    }
}
