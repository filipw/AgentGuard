// Standalone eng tool (not in AgentGuard.slnx). Two modes:
//
//   tokenizer-parity   Gate 2: confirm Microsoft.ML.Tokenizers' SentencePieceTokenizer over the
//                      mdeberta spm.model reproduces HF's text-portion ids on non-Latin scripts.
//                      Reads gate2_expected.json (dumped by eng/opir-eval/gate2_tokenizer_probe.py).
//
//   eval               Gate 5: reproduce the RESULTS.md section-3 multilingual recall/FPR through
//                      the C# inference path (prefix_ids ++ spm(text) ++ [SEP] -> ONNX -> per-label
//                      sigmoid -> max). Reads eval_multilingual.json (dumped by
//                      eng/opir-eval/dump_multilingual_eval.py). The inference here mirrors
//                      AgentGuard.Onnx.OpirModelSession; the production rule itself is covered by
//                      the gated E2E tests.
//
// Usage: dotnet run -c Release [tokenizer-parity|eval]   (default: tokenizer-parity)

using System.Text.Json;
using Microsoft.ML.OnnxRuntime;
using Microsoft.ML.OnnxRuntime.Tensors;
using Microsoft.ML.Tokenizers;

static string FindRepoRoot()
{
    var dir = AppContext.BaseDirectory;
    while (dir is not null && !File.Exists(Path.Combine(dir, "AgentGuard.slnx")))
        dir = Path.GetDirectoryName(dir);
    return dir ?? throw new InvalidOperationException("AgentGuard.slnx not found above the binary.");
}

var mode = args.Length > 0 ? args[0] : "tokenizer-parity";
var repoRoot = FindRepoRoot();
var modelDir = Path.Combine(repoRoot, "eng", "models", "opir-multilang");

return mode switch
{
    "tokenizer-parity" => RunTokenizerParity(modelDir),
    "eval" => RunEval(modelDir),
    _ => Fail($"unknown mode '{mode}' (expected tokenizer-parity | eval)"),
};

static int Fail(string msg)
{
    Console.Error.WriteLine(msg);
    return 2;
}

// ---------------------------------------------------------------------------
// tokenizer parity
// ---------------------------------------------------------------------------
static int RunTokenizerParity(string modelDir)
{
    var expectedPath = Path.Combine(modelDir, "gate2_expected.json");
    using var spmStream = File.OpenRead(Path.Combine(modelDir, "spm.model"));
    var tokenizer = SentencePieceTokenizer.Create(spmStream, addBeginningOfSentence: false, addEndOfSentence: false);

    using var doc = JsonDocument.Parse(File.ReadAllText(expectedPath));
    var samples = doc.RootElement.EnumerateArray().ToArray();

    var pass = 0;
    var byLangFail = new Dictionary<string, int>();
    var mismatches = new List<string>();

    foreach (var s in samples)
    {
        var lang = s.GetProperty("lang").GetString()!;
        var text = s.GetProperty("text").GetString()!;
        var expected = s.GetProperty("text_only_ids").EnumerateArray().Select(e => e.GetInt32()).ToArray();
        var got = tokenizer.EncodeToIds(text, maxTokenCount: 100_000, out _, out _).ToArray();

        if (got.SequenceEqual(expected))
        {
            pass++;
        }
        else
        {
            byLangFail[lang] = byLangFail.GetValueOrDefault(lang) + 1;
            if (mismatches.Count < 8)
            {
                var preview = text.Length > 40 ? text[..40] : text;
                mismatches.Add($"  [{lang}] {preview}\n    expected({expected.Length}) = [{string.Join(",", expected)}]\n    got     ({got.Length}) = [{string.Join(",", got)}]");
            }
        }
    }

    Console.WriteLine("Gate 2 C# SentencePiece parity over mdeberta spm.model");
    Console.WriteLine($"  samples: {samples.Length}");
    Console.WriteLine($"  exact id match: {pass}/{samples.Length}");
    if (mismatches.Count > 0)
    {
        Console.WriteLine($"  failures by lang: {string.Join(", ", byLangFail.Select(kv => $"{kv.Key}={kv.Value}"))}");
        foreach (var m in mismatches) Console.WriteLine(m);
    }
    Console.WriteLine(pass == samples.Length ? "PASS" : "FAIL");
    return pass == samples.Length ? 0 : 1;
}

// ---------------------------------------------------------------------------
// multilingual recall/FPR re-measure (C# inference path)
// ---------------------------------------------------------------------------
static int RunEval(string modelDir)
{
    var dataPath = Path.Combine(modelDir, "eval_multilingual.json");
    if (!File.Exists(dataPath))
        return Fail($"missing {dataPath} - run eng/opir-eval/dump_multilingual_eval.py first.");

    // fp16 is the default published build; mirror what the rule ships with.
    var modelFile = File.Exists(Path.Combine(modelDir, "model_fp16.onnx")) ? "model_fp16.onnx" : "model.onnx";
    Console.WriteLine($"model: {modelFile}");

    // load the frozen-taxonomy prefix
    using var prefixDoc = JsonDocument.Parse(File.ReadAllText(Path.Combine(modelDir, "prefix.json")));
    var prefixIds = prefixDoc.RootElement.GetProperty("prefix_ids").EnumerateArray().Select(e => e.GetInt64()).ToArray();
    var sepId = prefixDoc.RootElement.GetProperty("sep_id").GetInt64();
    var labels = prefixDoc.RootElement.GetProperty("labels").EnumerateArray().Select(e => e.GetString()!).ToArray();
    var unsafeLabels = prefixDoc.RootElement.TryGetProperty("unsafe_labels", out var ul)
        ? ul.EnumerateArray().Select(e => e.GetString()!).ToArray()
        : labels;
    // threshold over the harm categories only; the baked "safe and benign" sentinel is excluded.
    var unsafeIdx = unsafeLabels.Select(l => Array.IndexOf(labels, l)).ToArray();

    using var spmStream = File.OpenRead(Path.Combine(modelDir, "spm.model"));
    var tokenizer = SentencePieceTokenizer.Create(spmStream, addBeginningOfSentence: false, addEndOfSentence: false);
    // left for the process to reclaim on exit (avoids an ORT teardown abort on macOS).
    var session = new InferenceSession(Path.Combine(modelDir, modelFile));

    const int MaxLen = 512;

    float PUnsafe(string text)
    {
        var textBudget = Math.Max(0, MaxLen - prefixIds.Length - 1);
        var encoded = tokenizer.EncodeToIds(text, textBudget, out _, out _);
        var seqLen = prefixIds.Length + encoded.Count + 1;
        var ids = new long[seqLen];
        var mask = new long[seqLen];
        prefixIds.CopyTo(ids, 0);
        for (var i = 0; i < encoded.Count; i++) ids[prefixIds.Length + i] = encoded[i];
        ids[seqLen - 1] = sepId;
        Array.Fill(mask, 1L);

        var idTensor = new DenseTensor<long>(ids, [1, seqLen]);
        var maskTensor = new DenseTensor<long>(mask, [1, seqLen]);
        var inputs = new List<NamedOnnxValue>();
        foreach (var name in session.InputMetadata.Keys)
            inputs.Add(NamedOnnxValue.CreateFromTensor(name, name == "attention_mask" ? maskTensor : idTensor));

        using var results = session.Run(inputs);
        var logits = results[0].AsEnumerable<float>().ToArray();
        var max = float.NegativeInfinity;
        foreach (var idx in unsafeIdx)
        {
            var p = 1.0f / (1.0f + MathF.Exp(-logits[idx]));
            if (p > max) max = p;
        }
        return max;
    }

    using var dataDoc = JsonDocument.Parse(File.ReadAllText(dataPath));
    var rows = dataDoc.RootElement.EnumerateArray()
        .Select(r => (Lang: r.GetProperty("lang").GetString()!, Text: r.GetProperty("text").GetString()!, Label: r.GetProperty("label").GetInt32()))
        .ToArray();

    // score once, threshold offline
    var scored = rows.Select(r => (r.Lang, r.Label, P: PUnsafe(r.Text))).ToArray();
    float[] thresholds = [0.5f, 0.8f];
    var langs = scored.Select(s => s.Lang).Distinct().ToArray();

    Console.WriteLine();
    Console.WriteLine("Gate 5 multilingual re-measure (C# inference path) - compare to RESULTS.md section 3");
    Console.WriteLine($"  unsafe labels = {string.Join(", ", unsafeLabels)}");
    Console.WriteLine($"  block iff max-label sigmoid >= threshold");
    Console.WriteLine(new string('=', 16 + thresholds.Length * 18));
    var header = $"{"lang",-6}";
    foreach (var t in thresholds) header += $" | thr {t:0.0} rec/FPR";
    Console.WriteLine(header);
    Console.WriteLine(new string('-', 16 + thresholds.Length * 18));

    foreach (var lang in langs)
    {
        var line = $"{lang,-6}";
        foreach (var t in thresholds)
        {
            var ls = scored.Where(s => s.Lang == lang).ToArray();
            var pos = ls.Count(s => s.Label == 1);
            var neg = ls.Count(s => s.Label == 0);
            var tp = ls.Count(s => s.Label == 1 && s.P >= t);
            var fp = ls.Count(s => s.Label == 0 && s.P >= t);
            var rec = pos > 0 ? 100.0 * tp / pos : 0;
            var fpr = neg > 0 ? 100.0 * fp / neg : 0;
            line += $" | {rec,5:0}% /{fpr,4:0}%";
        }
        Console.WriteLine(line);
    }
    Console.WriteLine(new string('-', 16 + thresholds.Length * 18));
    Console.WriteLine("recall = % toxic blocked, FPR = % benign blocked. RESULTS.md (PyTorch) @0.5:");
    Console.WriteLine("  de 72/24  es 76/24  ru 52/16  ar 40/36  zh 40/28  hi 56/16");
    return 0;
}
