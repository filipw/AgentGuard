# Opir phase-0-light results

Model: `knowledgator/opir-multitask-large-v1.0` (GLiClass **two-tower**: DeBERTaV3-large
text encoder + `bge-small-en-v1.5` label encoder + cross-attention scorer). Run via the
upstream `gliclass` + `transformers` path (ground truth, no ONNX). Binary reduction:
block iff `P(unsafe) >= threshold`, `P(unsafe) = max sigmoid over the unsafe label set`.
Baselines: bundled Defender (minilm-multihead-v5, main 0.75 / aux 0.64, T=2.41) and
Azure AI Content Safety (`text:analyze`, FourSeverityLevels). CPU, ~4 inferences/sec.

recall = % unsafe blocked (higher better). FPR = % safe blocked (lower better).
Samples are small (hundreds); treat deltas under ~10pp as noise.

## 1. Injection axis - Opir loses to our existing stack

unsafe labels A = broad harm set; C = `prompt injection, jailbreak`. Defender at prod calibration.

| dataset | Defender | Opir-A | Opir-C |
|---|---|---|---|
| jackhhao jailbreak (HELD-OUT) | **90.6% / 0.8%** | 82.7% / 10.6% | 33.8% / 4.1% |
| deepset (HELD-OUT) | **56.7%** / 14.3% | 26.7% / 10.7% | 20.0% / 0.0% |
| BIPIA_code (indirect) | 34.0% | **54.0%** | 52.0% |
| BIPIA_text (indirect) | 12.0% | **41.3%** | 29.3% |
| NotInject FPR (over-defense) | 10.3% | 19.8% | 7.7% |
| WildGuard-Benign FPR | 7.1% | 22.6% | 6.8% |

Defender beats Opir on both held-out injection sets (recall and FPR). Opir's only
injection edge is indirect/code (BIPIA), which PIGuard already does at ~96% vs Opir 54%.
**Opir adds no injection capability we lack.**

## 2. Content-safety axis - the gap Opir was meant to fill (balanced 50/50 samples)

unsafe labels = `toxicity, hate speech, violence, sexual content, self-harm, harassment`.

| dataset | Defender (sev n/a) | Opir thr 0.5 | Azure sev>=2 |
|---|---|---|---|
| OpenAI-moderation (multi-harm) | 14% / 8% | 86% / 36% | 98% / 48% |
| toxic-conversations (toxicity) | 10% / 4% | 58% / 18% | 98% / 62% |

Defender barely detects content harms (14% / 10%) - the offline content-safety gap is
**real**. Opir does detect them. But note Azure (a mature product) *also* posts 48-62%
FPR on these "benign" negatives, i.e. the negatives are hard / borderline / noisy, not
proof that Opir is uniquely trigger-happy.

### Operating-point sweep (score once, threshold offline)

| OpenAI-moderation | Opir rec/FPR | | Azure rec/FPR |
|---|---|---|---|
| thr 0.50 | 86% / 36% | sev>=2 | 98% / 48% |
| thr 0.80 | 82% / 36% | sev>=4 | **82% / 8%** |
| thr 0.90 | 80% / 36% | sev>=6 | 40% / 0% |

| toxic-conversations | Opir rec/FPR | | Azure rec/FPR |
|---|---|---|---|
| thr 0.50 | 58% / 18% | sev>=2 | 98% / 62% |
| thr 0.80 | 54% / 14% | sev>=4 | 8% / 4% |
| thr 0.90 | 40% / 14% | sev>=6 | 2% / 2% |

Opir over-blocks clearly-benign text too (WildGuard-benign FPR 21% @0.5, 17% @0.9;
CS-benign 9% / 6%), and its FPR is **threshold-insensitive** - the false positives are
scored at ~1.0 confidence, so raising the threshold does not rescue them.

## Reading

1. **Azure wins on its own categories.** At sev>=4 Azure is 82% / **8%** on
   OpenAI-moderation - same recall as Opir's best, ~4.5x lower FPR. As an offline
   *replacement* for Azure on hate/sexual/violence/self-harm, Opir is not competitive.
2. **Opir's only real edge is generic toxicity/insults** (toxic-conversations), which
   do not map to Azure's 4 categories: Opir holds 54% / 14% at 0.8 where Azure collapses
   to 8% recall at sev>=4. Real, but modest in absolute terms.
3. **Threshold-insensitive FPR** is a structural weakness for a single-`P(unsafe)`
   reduction; per-category thresholds might help but the confident-FP pattern caps upside.

## 3. Multilingual toxicity - Opir-multilang fills a real offline gap

Model `knowledgator/opir-multitask-multilang-v1.0` (mDeBERTaV3). Data:
`textdetox/multilingual_toxicity_dataset` (per-language splits, balanced 25/class).
3-way at Opir thr 0.5 / Azure sev>=2:

| lang | Defender rec/FPR | Opir-ml rec/FPR | Azure sev>=2 rec/FPR |
|---|---|---|---|
| de | 72% / 68% | 72% / 24% | 92% / 52% |
| es | 4% / 20% | 76% / 24% | 92% / 20% |
| ru | 0% / 0% | 52% / 16% | 76% / 8% |
| ar | 0% / 0% | 40% / 36% | 84% / 24% |
| zh | 0% / 0% | 40% / 28% | 44% / 32% |
| hi | 0% / 0% | 56% / 16% | 64% / 4% |

Operating curve (Opir thr vs Azure severity):

| | Opir 0.5 | Opir 0.8 | Azure sev>=2 | Azure sev>=4 |
|---|---|---|---|---|
| de | 72/24 | 52/20 | 92/48 | **8/0** |
| es | 76/24 | 60/24 | 92/20 | **28/0** |
| ru | 52/16 | 32/8 | 76/8 | **0/0** |
| ar | 40/36 | 24/20 | 84/24 | **12/0** |
| zh | 40/28 | 20/20 | 44/32 | **8/0** |
| hi | 56/16 | 36/4 | 64/4 | **4/0** |

Reading:
1. **Defender is useless off-English** (0% recall on ru/ar/zh/hi; de "72%" is at 68% FPR
   i.e. blocking nearly everything). The multilingual gap is real and total.
2. **Azure has no clean non-English operating point.** Its severity calibration does not
   transfer: toxic non-English text is scored at exactly severity 2, so sev>=4 collapses
   recall to ~0-28% (bold column). Azure's only viable non-English point is sev>=2, where
   FPR is high (de 48%, zh 32%, ar 24%). This is unlike English, where sev>=4 was the
   82%/8% sweet spot.
3. **Opir-multilang gives genuine, offline coverage** where AgentGuard has none today:
   40-76% recall at 16-36% FPR (best on European es/de, weaker on ar/zh). It does not
   beat Azure-sev>=2 on recall, but it is in the same ballpark, with comparable-or-lower
   FPR on de/zh - and it is local, free, and PII-safe.

(textdetox negatives are real social-media comments and partly borderline - Azure flags
~48% of German "benign" - so absolute FPRs are inflated by the benchmark, for all models.)

## Verdict (split)

- **English (large variant): do not integrate.** Loses to Defender/PIGuard on injection
  and to Azure (sev>=4, 82%/8%) on content-safety; only a marginal generic-toxicity edge.
  Not worth the two-tower ONNX cost.
- **Multilingual variant: promising for the offline non-English niche - worth a deeper
  Phase-0.5 before C#.** It is the only option that gives any non-English content-safety
  coverage offline (Defender 0%, Azure cloud/per-call/PII-bound with no clean non-English
  operating point). Position as a *sovereign/offline multilingual* guard complementing
  (not replacing) Azure, mirroring how Defender is positioned for English injection.

### Integration cost - much lower than the English variant

The multilang variant is architecturally cheaper than the large one. From its config:
`architecture_type: uni-encoder`, `label_model_name: None`, `scorer_type: simple`,
`pooling: first`, text encoder `microsoft/mdeberta-v3-base`, `vocab_type: spm`.

So it is **not** the two-tower (no separate `bge-small-en` label encoder): labels are
prepended as tokens and run through a single mDeBERTaV3 forward pass. That makes it
**PIGuard-shaped** - one ONNX graph + the DeBERTa **SentencePiece** tokenizer AgentGuard
already wires - plus a GLiClass label-prepend/pooling wrapper. Far less work than the
multi-graph two-tower flagged for the large variant.

### Next (Phase-0.5, before any C#)
- Widen languages (the full textdetox 15 + check Opir's claimed 23) and bump samples for
  tighter CIs; tune the Opir threshold per deployment (FPR *is* somewhat tunable here,
  unlike the English run - e.g. hi 36%/4% at 0.8).
- Confirm an ONNX export of the uni-encoder behaves (reuse the PIGuard export/fp16 path)
  and that English harm labels are the right choice for non-English text (try native-
  language label strings as a variant).

Repro: `opcurve.py [--multilingual --model ...]`, `eval.py --multilingual --with-azure`,
`eval.py --content-safety --with-azure`. Azure billed ~1200 records total for this analysis.
