// Standalone eng tool (not in AgentGuard.slnx). Gate 2/3 parity probe for the GLiNER span NER.
//
//   parity   For each fixture (eng/models/gliner/fixtures.json): reproduce the GLiNER input
//            assembly in C# (per-word spm encode + manual <<ENT>>/<<SEP>>/CLS/SEP ids + words_mask +
//            span_idx/span_mask), assert it matches the gliner-lib collated tensors id-for-id
//            (Gate 2), run the ONNX model, sigmoid + threshold + flat-greedy decode, and assert the
//            decoded char spans/labels reproduce the library's predict_entities output (Gate 3).
//
// Usage: dotnet run -c Release            (default mode: parity)
//
// Mirrors AgentGuard.Onnx.GlinerModelSession. Requires eng/download-gliner-model.sh + export_onnx.py
// to have populated eng/models/gliner/.

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

var repoRoot = FindRepoRoot();
var modelDir = Path.Combine(repoRoot, "eng", "models", "gliner");
var fixturesPath = Path.Combine(modelDir, "fixtures.json");
var configPath = Path.Combine(modelDir, "config.json");
var spmPath = Path.Combine(modelDir, "spm.model");
var modelPath = Path.Combine(modelDir, "model.onnx");

foreach (var p in new[] { fixturesPath, configPath, spmPath, modelPath })
{
    if (!File.Exists(p))
    {
        Console.Error.WriteLine($"missing {p}. Run eng/gliner-eval/export_onnx.py first.");
        return 2;
    }
}

using var cfgDoc = JsonDocument.Parse(File.ReadAllText(configPath));
var cfg = cfgDoc.RootElement;
long clsId = cfg.GetProperty("cls_id").GetInt64();
long sepId = cfg.GetProperty("sep_id").GetInt64();
long entTokenId = cfg.GetProperty("ent_token_id").GetInt64();
long sepTokenId = cfg.GetProperty("sep_token_id").GetInt64();
int maxWidth = cfg.GetProperty("max_width").GetInt32();

using var spmStream = File.OpenRead(spmPath);
var tokenizer = SentencePieceTokenizer.Create(spmStream, addBeginningOfSentence: false, addEndOfSentence: false);
using var session = new InferenceSession(modelPath);
var inputNames = session.InputMetadata.Keys.ToArray();

using var fxDoc = JsonDocument.Parse(File.ReadAllText(fixturesPath));
var fixtures = fxDoc.RootElement.EnumerateArray().ToArray();

int gate2Pass = 0, gate3Pass = 0, total = 0;
foreach (var fx in fixtures)
{
    total++;
    var text = fx.GetProperty("text").GetString()!;
    var labels = fx.GetProperty("labels").EnumerateArray().Select(e => e.GetString()!).ToArray();
    var words = fx.GetProperty("tokens").EnumerateArray().Select(e => e.GetString()!).ToArray();
    var startMap = fx.GetProperty("start_token_map").EnumerateArray().Select(e => e.GetInt32()).ToArray();
    var endMap = fx.GetProperty("end_token_map").EnumerateArray().Select(e => e.GetInt32()).ToArray();
    var expIds = fx.GetProperty("input_ids").EnumerateArray().Select(e => e.GetInt64()).ToArray();
    var expMask = fx.GetProperty("words_mask").EnumerateArray().Select(e => e.GetInt64()).ToArray();
    int numWords = fx.GetProperty("text_lengths").EnumerateArray().First().GetInt32();

    // ---- C# input assembly (mirrors GlinerModelSession.AssembleInput) ----
    var ids = new List<long> { clsId };
    var mask = new List<long> { 0 };
    foreach (var label in labels)
    {
        ids.Add(entTokenId); mask.Add(0);
        foreach (var s in tokenizer.EncodeToIds(label)) { ids.Add(s); mask.Add(0); }
    }
    ids.Add(sepTokenId); mask.Add(0);
    for (var wi = 0; wi < words.Length; wi++)
    {
        var sub = tokenizer.EncodeToIds(words[wi]).ToArray();
        for (var j = 0; j < sub.Length; j++) { ids.Add(sub[j]); mask.Add(j == 0 ? wi + 1 : 0); }
    }
    ids.Add(sepId); mask.Add(0);

    var idsArr = ids.ToArray();
    var maskArr = mask.ToArray();
    bool idsOk = idsArr.SequenceEqual(expIds);
    bool maskOk = maskArr.SequenceEqual(expMask);
    if (idsOk && maskOk) gate2Pass++;
    Console.WriteLine($"[{text[..Math.Min(46, text.Length)],-46}]");
    Console.WriteLine($"  Gate2 input_ids={(idsOk ? "OK" : "MISMATCH")} words_mask={(maskOk ? "OK" : "MISMATCH")} (len {idsArr.Length} vs {expIds.Length})");
    if (!idsOk)
    {
        Console.WriteLine($"    c#  : {string.Join(",", idsArr)}");
        Console.WriteLine($"    lib : {string.Join(",", expIds)}");
    }

    // ---- run + decode (mirrors GlinerModelSession.ScoreChunk/Enumerate/GreedyFlatDecode) ----
    int numSpans = numWords * maxWidth;
    var spanIdx = new long[numSpans * 2];
    var spanMask = new bool[numSpans];
    for (var s = 0; s < numWords; s++)
        for (var w = 0; w < maxWidth; w++)
        {
            var f = s * maxWidth + w;
            spanIdx[f * 2] = s; spanIdx[f * 2 + 1] = s + w; spanMask[f] = (s + w) < numWords;
        }
    var attn = new long[idsArr.Length];
    Array.Fill(attn, 1L);

    var feeds = new List<NamedOnnxValue>();
    foreach (var name in inputNames)
    {
        NamedOnnxValue v = name switch
        {
            "attention_mask" => NamedOnnxValue.CreateFromTensor(name, new DenseTensor<long>(attn, [1, idsArr.Length])),
            "words_mask" => NamedOnnxValue.CreateFromTensor(name, new DenseTensor<long>(maskArr, [1, maskArr.Length])),
            "text_lengths" => NamedOnnxValue.CreateFromTensor(name, new DenseTensor<long>(new long[] { numWords }, [1, 1])),
            "span_idx" => NamedOnnxValue.CreateFromTensor(name, new DenseTensor<long>(spanIdx, [1, numSpans, 2])),
            "span_mask" => NamedOnnxValue.CreateFromTensor(name, new DenseTensor<bool>(spanMask, [1, numSpans])),
            _ => NamedOnnxValue.CreateFromTensor(name, new DenseTensor<long>(idsArr, [1, idsArr.Length])),
        };
        feeds.Add(v);
    }

    using var res = session.Run(feeds);
    var logits = res[0].AsEnumerable<float>().ToArray(); // [1, L, K, C]
    int numClasses = labels.Length;

    var cands = new List<(int s, int e, string label, float score)>();
    for (var s = 0; s < numWords; s++)
        for (var w = 0; w < maxWidth; w++)
        {
            int end = s + w;
            if (end >= numWords) continue;
            int bIdx = (s * maxWidth + w) * numClasses;
            for (var c = 0; c < numClasses; c++)
            {
                float prob = 1f / (1f + MathF.Exp(-logits[bIdx + c]));
                if (prob >= 0.5f) cands.Add((s, end, labels[c], prob));
            }
        }

    // flat greedy
    var sorted = cands.OrderByDescending(x => x.score).ToList();
    var sel = new List<(int s, int e, string label, float score)>();
    foreach (var c in sorted)
    {
        bool ov = sel.Any(x => (x.s == c.s && x.e == c.e) || !(c.s > x.e || x.s > c.e));
        if (!ov) sel.Add(c);
    }
    sel.Sort((a, b) => a.s.CompareTo(b.s));

    var decodedCs = sel.Select(c => (start: startMap[c.s], end: endMap[c.e], c.label, c.score)).ToList();
    var expDecoded = fx.GetProperty("decoded").EnumerateArray()
        .Select(e => (start: e.GetProperty("start").GetInt32(), end: e.GetProperty("end").GetInt32(),
                      label: e.GetProperty("label").GetString()!, score: (float)e.GetProperty("score").GetDouble()))
        .ToList();

    bool decodeOk = decodedCs.Count == expDecoded.Count &&
        decodedCs.Zip(expDecoded).All(p => p.First.start == p.Second.start && p.First.end == p.Second.end && p.First.label == p.Second.label);
    if (decodeOk) gate3Pass++;
    Console.WriteLine($"  Gate3 decode={(decodeOk ? "OK" : "MISMATCH")} (c# {decodedCs.Count} vs lib {expDecoded.Count})");
    foreach (var d in decodedCs)
        Console.WriteLine($"     c#  {d.label,-13} [{d.start},{d.end}) {d.score:F3}  '{text[d.start..d.end]}'");
    if (!decodeOk)
        foreach (var d in expDecoded)
            Console.WriteLine($"     lib {d.label,-13} [{d.start},{d.end}) {d.score:F3}");
    Console.WriteLine();
}

Console.WriteLine($"Gate 2 (assembly parity): {gate2Pass}/{total}");
Console.WriteLine($"Gate 3 (decode parity):   {gate3Pass}/{total}");
return gate2Pass == total && gate3Pass == total ? 0 : 1;
