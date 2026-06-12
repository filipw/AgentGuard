# Opir (GLiClass) - Phase-0-light read

A throwaway measurement harness (Python, not in `AgentGuard.slnx`) that bootstraps
Knowledgator's [Opir](https://github.com/Knowledgator/Opir) safety classifier into a
usable form and scores it on AgentGuard's existing held-out / over-defense sets,
beside the bundled StackOne **Defender** model.

The question it answers: *is Opir worth a real C# (ONNX) integration, and which
variant?* It ships nothing.

## Why this is not a drop-in of the piguard-eval harness

Opir is **not** a plain sequence classifier. It is a **GLiClass** label-conditioned
encoder: candidate labels are jointly encoded with the input in a single forward
pass, producing a per-label score. We run it through its own upstream `gliclass`
+ `transformers` path (ground truth, no ONNX export yet) and reduce the multi-task
model to a binary guard:

> block iff `P(unsafe) >= --threshold` (default 0.5), where `P(unsafe)` is the max
> sigmoid score over the `--unsafe-labels` set (multi-label mode).

The first integration target is the **cheap DeBERTa-backed variant**
(`knowledgator/opir-multitask-large-v1.0`, DeBERTaV3-large) because it reuses the
SentencePiece tokenizer path AgentGuard already wires for Defender/PIGuard. Swap in
the multilingual mDeBERTaV3 or the edge (Ettin/mmBERT) variants with `--model`.

## Caveat on label choice

Opir is a *general* safety classifier (toxicity / hate / violence / jailbreak / ...),
not an injection specialist. Scoring it on our injection sets with a single `unsafe`
label is a **lower bound**. Use `--unsafe-labels "unsafe,prompt injection,jailbreak"`
to probe the ceiling, and treat its content-safety / multilingual behaviour (the real
gap it would fill) as the deciding factor, not raw injection recall.

## Datasets

Identical to `eng/piguard-eval` so the columns line up:

| Set | Polarity | Source |
|-----|----------|--------|
| NotInject (one/two/three) | benign (over-defense) | PIGuard repo |
| WildGuard-Benign | benign | PIGuard repo |
| BIPIA_code | malicious | PIGuard repo |
| BIPIA_text | "malicious"* | PIGuard repo |
| CS-benign | benign | inline (from `eng/defender-sweep`) |
| jackhhao jailbreak (test) | mixed, held-out | HF datasets-server |
| deepset prompt-injections (test) | mixed, held-out | HF datasets-server |

\* BIPIA_text are benign-looking automation prompts framed as indirect injection;
do not read its recall as ordinary attack detection.

## Run

```bash
cd eng/opir-eval
./fetch_datasets.sh                                  # one-time: pull PIGuard's eval JSON
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt

# injection axis (vs bundled Defender)
.venv/bin/python eval.py --skip-hf --max-rows 25     # fast smoke run
.venv/bin/python eval.py                             # full side-by-side vs Defender

# content-safety axis (the gap Opir would fill) - small balanced samples
.venv/bin/python eval.py --content-safety                       # Opir + Defender
.venv/bin/python eval.py --content-safety --with-azure          # + Azure AI Content Safety
.venv/bin/python opcurve.py                                     # Opir-vs-Azure operating curve

# multilingual variant (the one untested place with a real AgentGuard gap)
.venv/bin/python eval.py --content-safety --model knowledgator/opir-multitask-multilang-v1.0
```

First run downloads the Opir weights from HuggingFace (DeBERTaV3-large is ~1.7 GB
fp32) and caches HF rows under `.cache/` (gitignored). CPU is fine; pass
`--device mps` on Apple silicon or `--device cuda:0` on a GPU box.

`--with-azure` reads `AZURE_CONTENT_SAFETY_ENDPOINT` / `AZURE_CONTENT_SAFETY_KEY` from
the repo-root `.env` (or environment) and **bills one record per text** - it is throttled
under the free-tier 5 RPS and kept to small samples via `--per-class`.

## Reading the output

- **recall** = % of unsafe blocked (higher better).
- **FPR** = % of safe blocked (lower better). On NotInject this is the over-defense rate.

## Outcome

See [RESULTS.md](RESULTS.md). Summary: Opir (English large variant) loses to
Defender/PIGuard on injection and to Azure (severity>=4) on the content-safety harms
Azure covers; its only edge is generic toxicity. **Not integrated.** The one open thread
is the **multilingual** variant for offline non-English content safety - the only
scenario with a real gap (Defender is English-only, Azure is cloud/per-call).
