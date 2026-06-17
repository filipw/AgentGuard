# GLiNER span NER eval harness (AgentGuard.Pii Stage 3)

Offline tooling to export a GLiNER span NER model to ONNX, validate C# parity, and pick the
operating threshold for the AgentGuard offline named-entity recognizer (PERSON / LOCATION /
ORGANIZATION / DATE_TIME). Not in `AgentGuard.slnx`; CPU-only.

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python export_onnx.py     # Gate 1: export + dump fixtures.json + config.json
python fp16_onnx.py       # fp16 build (default delivery)
python eval.py            # Gate 4: per-entity P/R/F1 + threshold sweep
```

Model: [`urchade/gliner_multi_pii-v1`](https://huggingface.co/urchade/gliner_multi_pii-v1)
(mDeBERTa-v3-base backbone, Apache-2.0). Zero-shot: the entity labels are part of the runtime
input, not a frozen taxonomy, so there is **no prefix.json** - the C# side reproduces the input
assembly and decode at inference time. Outputs land in `eng/models/gliner/` (gitignored).

## Gate 1 - confirmed ONNX signature (gliner 0.2.27, `UniEncoderSpanGLiNER`, opset 19)

Inputs:

| name | dtype | shape |
|------|-------|-------|
| `input_ids` | int64 | `[batch, seq]` |
| `attention_mask` | int64 | `[batch, seq]` |
| `words_mask` | int64 | `[batch, seq]` |
| `text_lengths` | int64 | `[batch, 1]` |
| `span_idx` | int64 | `[batch, num_spans, 2]` |
| `span_mask` | bool | `[batch, num_spans]` |

Output: `logits` float `[batch, num_words(L), max_width(K), num_classes(C)]`.

Special tokens (baked into `config.json` for the C# side): `<<ENT>>`=250103, `<<SEP>>`=250104,
CLS=1, SEP=2, PAD=0. `max_width`=12. Word splitter: `whitespace` = regex `\w+(?:[-_]\w+)*|\S`.

### Input assembly (reproduced in C# `GlinerModelSession.AssembleInput`)

Word-level prompt `[<<ENT>> label1 ... <<ENT>> labelN <<SEP>> word1 ... wordM]` is subword-tokenized
(`is_split_into_words`) into

```
[CLS] (<<ENT>> label-subwords)xN <<SEP>> word-subwords... [SEP]
```

`words_mask` marks the first subword of each TEXT word with its 1-based index (prompt/special/
continuation subwords -> 0). Each word is SentencePiece-encoded independently (with its own ▁ dummy
prefix), which reproduces HF's `is_split_into_words` ids id-for-id.

### Span enumeration + decode (reproduced in C# `EnumerateCandidates` / `GreedyFlatDecode`)

`span_idx` = every `(start, start+w)` for `start in [0,L)`, `w in [0,max_width)`; `span_mask` =
`start+w < L`. `logits[start][w][class]` -> `sigmoid` -> keep `>= threshold` and valid -> flat-greedy
non-overlap (sort by score desc, drop any span overlapping an accepted one; equal word ranges
overlap) -> map word span to chars via `start_token_map[start] .. end_token_map[end]`.

## Gate 2/3 - C# parity (`eng/gliner-csharp-eval`)

```bash
cd ../gliner-csharp-eval && dotnet run -c Release
```

Replays `fixtures.json` through the C# assembly + decode and asserts id-for-id (Gate 2) and
span-for-span (Gate 3) against the gliner library. Measured: assembly parity 4/5, decode parity 5/5
across en / de / ru / ar / zh. The single Gate-2 miss is a CJK fullwidth-punctuation edge (HF emits
`[UNK]`, SentencePiece emits its piece) on text the whitespace splitter cannot word-segment anyway;
it detects 0 entities, so decode is unaffected. NER coverage is for whitespace-segmented scripts
(Latin / Cyrillic / Arabic / Devanagari); CJK is out of practical scope for this splitter.

## fp16

`fp16_onnx.py` uses the same realign-stale-Cast pass as `eng/opir-eval/fp16_onnx.py`. fp16 is
~580 MB and numerically equivalent to fp32 (max |delta P(span)| 0.0043 on the multilingual probes).
fp16 is the default download.
