# Phase-0 results: PIGuard vs Defender as standalone single-shot guards

Measured 2026-06-11 with `eval.py` (PIGuard via `transformers` ground-truth path;
Defender via bundled `minilm-multihead-v5` ONNX + production dual-head calibration).
Harness validated: PIGuard NotInject over-defense FPR 11.5% => ~88.5% accuracy,
matching the paper's ~87%.

## Headline table (block rates)

`recall` = % malicious blocked (higher better). `FPR` = % benign blocked (lower better).

| Dataset | n | polarity | Defender 0.75/0.64 | PIGuard @0.5 (argmax) | PIGuard @0.9 |
|---|---|---|---|---|---|
| NotInject (over-defense) | 339 | benign | 10.3% FPR | 11.5% FPR | **8.3% FPR** |
| WildGuard-Benign | 971 | benign | **7.1% FPR** | 23.9% FPR | 10.9% FPR |
| CS-benign (built-in) | 34 | benign | 11.8% FPR | 14.7% FPR | **8.8% FPR** |
| BIPIA_code (injection) | 50 | malicious | 34.0% rec | **98.0% rec** | 96.0% rec |
| BIPIA_text (injection*) | 75 | malicious* | 12.0% | 38.7% | 25.3% |
| jackhhao jailbreak (held-out for Defender)¹ | 262 | mixed | 90.6% rec / 0.8% FPR | 95.7% / 4.9% | 93.5% / 0.8% |
| deepset (held-out for Defender)¹ | 116 | mixed | 56.7% rec / 14.3% FPR | 66.7% / 0.0% | 46.7% / 0.0% |

¹ `jackhhao` and `deepset` are **in PIGuard's training set** -> PIGuard numbers optimistic; held-out for Defender only.
\* BIPIA_text = benign-looking automation prompts PIGuard labels "injection"; low block here is arguably correct, not a miss.

## Multilingual probe (NotInject, benign only)

| subset | n | Defender | PIGuard@0.5 | PIGuard@0.9 |
|---|---|---|---|---|
| Multilingual | 84 | 0.0% FPR | 0.0% | 0.0% |
| English/other | 255 | 13.7% FPR | 15.3% | 11.0% |

Over-defense is entirely an English-imperative phenomenon for both models (consistent
with the "show me X" note in CLAUDE.md). Neither over-blocks benign multilingual text.
This does NOT test multilingual *attack* recall (no such set here) - that gap is unresolved.

## Findings

1. **The argmax (0.5) default is a trap.** At 0.5 PIGuard over-blocks benign text
   (WildGuard 23.9% FPR) and does not beat Defender on over-defense. Use ~0.9.
2. **At threshold 0.9 PIGuard is the stronger standalone injection guard.** It
   matches-or-beats Defender's benign FPR on 2 of 3 benign sets (NotInject 8.3 vs 10.3,
   CS-benign 8.8 vs 11.8; WildGuard 10.9 vs 7.1 is its one benign loss), matches held-out
   jailbreak recall (93.5% / 0.8%), and **dominates on indirect/code injection**
   (BIPIA_code 96% vs Defender's 34%) - the category Defender most badly misses.
3. **Defender's edge is size and benign-chat FPR.** 22 MB int8 / ~8 ms vs PIGuard's
   184 M params / ~0.7 GB fp32 / ~15 ms, and lower FPR on general benign chat (WildGuard).
4. **Strong stack complement.** BIPIA_code (34% -> 96%) is exactly Defender's blind spot,
   so even if not chosen as the standalone default, PIGuard is a high-value second layer.

## Phase 1: ONNX export + C# repro (validated)

- **Export.** `export_onnx.py` exports the real custom forward (DebertaV2 encoder +
  `Linear` on the CLS hidden state) to `eng/models/piguard/model.onnx` (736 MB fp32,
  opset 17, legacy exporter). PyTorch-vs-ONNX max abs logit diff **1.05e-05** (PASS).
- **C# repro.** `eng/piguard-csharp-eval` loads that ONNX + the SentencePiece model and
  **reproduces the Python @0.9 numbers exactly** (NotInject 8.3%, WildGuard 10.9%,
  BIPIA_code 96.0%, CS-benign 8.8%, jackhhao 93.5%/0.8%, deepset 46.7%/0%). Tokenizer
  fidelity gate (full `input_ids` vs HF) passes on all probes incl. Chinese.

### Model format / size (shipping)

| Format | Size | C# accuracy | Verdict |
|--------|------|-------------|---------|
| fp32 (`model.onnx`) | 736 MB | exact repro | works |
| int8 dynamic | 243 MB | **broken** (everything passes, BIPIA_code 96%->0%) | unusable - DeBERTa disentangled attention collapses under dynamic int8 |
| **fp16 (`model_fp16.onnx`)** | **369 MB** | **exact repro (identical to fp32, all datasets)** | **recommended shipping format** |

fp16 is the shipping target: half the size, numerically identical (P(injection) deltas
0.0000 vs fp32; C# dataset numbers match exactly). The naive onnxconverter_common fp16 pass
leaves stale `Cast` `to` attributes (the int64->FLOAT mask casts) that ORT rejects; the fix
(`eng/piguard-eval/fp16_onnx.py`) realigns every Cast's `to` attribute with its declared output
type, recursing into the `If` control-flow subgraphs DeBERTa's export contains. int8 is dead
(disentangled attention can't take dynamic quant); op-type block lists are pathologically slow
(O(n^2) cast insertion on 4.5k nodes).

### Two integration gotchas found

1. **spm.model is an unmaterialized LFS pointer in `leolee99/PIGuard`** (132-byte text
   stub). The Python fast tokenizer used `tokenizer.json` so it never noticed. The real
   SentencePiece model must come from the stock `microsoft/deberta-v3-base` backbone
   (verified: produces identical ids). Bundle/download *that* spm.model, not PIGuard's.
2. **`SentencePieceTokenizer.Create` defaults to `addBeginningOfSentence: true`**, which
   prepends a BOS (id 1 = the same id as `[CLS]` for deberta-v3). Manually wrapping with
   CLS then yields a *double* id-1. Must construct with `addBeginningOfSentence: false,
   addEndOfSentence: false`. NOTE: the existing shipped `OnnxPromptInjectionRule`
   (ProtectAI deberta-v3, order 12) uses the default `Create()` and *also* manually adds
   CLS - so it likely has a latent double-CLS bug on deberta-v3 spm. Flagged separately.

## Caveats

- BIPIA_code is only 50 samples; the headline win rests on a small set (though the gap is huge).
- PIGuard needs `trust_remote_code` + a custom `model_type: piguard` head -> ONNX export
  fidelity is a real Phase-1 risk to validate before any C# integration.
