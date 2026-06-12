# PIGuard vs Defender - Phase-0 standalone comparison

A throwaway measurement harness (Python, not in `AgentGuard.slnx`) that scores the
[`leolee99/PIGuard`](https://huggingface.co/leolee99/PIGuard) DeBERTa-v3 model and
the bundled StackOne **Defender** multi-head model side by side, each as a
**standalone single-shot prompt-injection guard**.

The question it answers: *if a user wires up only one ML guard, which performs
better?* It is a decision tool for whether PIGuard is worth a real C# integration -
it does **not** ship anything.

## Fidelity

- **PIGuard** runs through its own upstream `transformers` path (`trust_remote_code`,
  argmax => block iff `P(injection) >= --pi-threshold`, default 0.5). This is ground
  truth - no ONNX export involved at this stage.
- **Defender** runs the bundled `minilm-multihead-v5` ONNX with the exact production
  dual-head calibration (`block iff sigmoid(main/T) >= mainThr AND sigmoid(aux/T) < auxThr`,
  `T=2.41`, `mainThr=0.75`, `auxThr=0.64`), mirroring
  `AgentGuard.Onnx.DefenderModelSession`. Uses the model files under
  `eng/models/minilm-prompt-injection/`.

## Datasets

| Set | Polarity | Source |
|-----|----------|--------|
| NotInject (one/two/three) | benign (over-defense) | PIGuard repo |
| WildGuard-Benign | benign | PIGuard repo |
| BIPIA_code | malicious | PIGuard repo |
| BIPIA_text | "malicious"* | PIGuard repo |
| CS-benign | benign | inline (from `eng/defender-sweep`) |
| jackhhao jailbreak (test) | mixed, held-out | HF datasets-server |
| deepset prompt-injections (test) | mixed, held-out | HF datasets-server |

\* PIGuard labels BIPIA_text's benign-looking automation prompts as "injection"
(BIPIA's indirect-injection framing). Reported separately; do not read its recall
as ordinary attack detection.

> Caveat: `deepset/prompt-injections` and `jackhhao/jailbreak-classification` are in
> **PIGuard's training set**, so PIGuard's numbers on them are optimistic. They are
> held-out for *Defender*. Trust NotInject / WildGuard / BIPIA for a fair PIGuard read.

## Run

```bash
cd eng/piguard-eval
./fetch_datasets.sh                       # one-time: pull PIGuard's eval JSON
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python eval.py                  # full side-by-side
.venv/bin/python eval.py --skip-hf        # only the offline bundled sets
.venv/bin/python eval.py --pi-threshold 0.9   # stricter PIGuard operating point
```

First run downloads the PIGuard weights (~0.7 GB, fp32) from HuggingFace and caches
HF rows under `.cache/` (gitignored).

## Reading the output

- **recall** = % of malicious blocked (higher better).
- **FPR** = % of benign blocked (lower better). On NotInject this is the over-defense
  rate; PIGuard's paper reports ~13% (=> ~87% over-defense accuracy), a useful sanity
  check that the harness is wired correctly.
