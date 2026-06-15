# classifier-benchmark

Benchmarks the **real** AgentGuard prompt-injection rules side by side on held-out datasets,
reporting precision / recall / F1 / FPR per classifier. Standalone eng tool, not in
`AgentGuard.slnx`.

Unlike `eng/defender-sweep` (which re-implements Defender scoring inline to sweep thresholds),
this references `AgentGuard.Core` and `AgentGuard.Onnx` and runs the actual rules through
`IGuardrailRule.EvaluateAsync`, so the numbers reflect what ships.

## Classifiers

| Column | Rule | Notes |
|--------|------|-------|
| `regex-medium` | `PromptInjectionRule` (Sensitivity.Medium) | Arcanum-taxonomy patterns, default tier |
| `regex-high` | `PromptInjectionRule` (Sensitivity.High) | all patterns |
| `defender` | `DefenderPromptInjectionRule` | bundled minilm-multihead-v5, prod calibration |
| `llm (<model>)` | `LlmPromptInjectionRule` | LLM-as-judge over an OpenAI-compatible endpoint |

## Datasets

Held-out (not in the Defender v5 training set), fetched via the HF datasets-server JSON rows API
and cached under `.cache/` (gitignored):

- `jackhhao/jailbreak-classification` (test) - English jailbreaks + benign
- `deepset/prompt-injections` (test) - German-heavy injections + benign
- a built-in English customer-service benign corpus (false-positive mode)

## Usage

```bash
cd eng/classifier-benchmark
dotnet run -c Release -- --max-rows 25             # balanced 25/class per dataset (quick LLM read)
dotnet run -c Release -- --skip-llm                # regex + Defender only (fast, full sets)
dotnet run -c Release                              # all rows (LLM column is slow - see below)
dotnet run -c Release -- --concurrency 2           # 2 LLM requests in flight (default 1)
```

LLM endpoint and model default to `OPENAI_BASE_URL` / `OPENAI_MODEL` (or the values hard-coded at
the top of `Program.cs`). The LLM column issues **one request per row, sequentially by default**
(`--concurrency 1`) to stay gentle on a local model - it dominates runtime, so use `--max-rows`
for a quick read. The instant local rules (regex, Defender) always run on the full set.
`--llm-max-tokens` (default 4000) gives reasoning models room to think before answering;
`--llm-timeout` (default 240s) caps a single runaway request.

## Caveats

- `LlmPromptInjectionRule` fails **open** on errors (an LLM timeout counts as "not blocked"), so a
  flaky or overloaded endpoint inflates the LLM's false-negative rate. Keep `--concurrency` within
  what the server handles cleanly.
- `--max-rows N` takes the first N positives and N negatives per dataset (balanced), preserving
  dataset order.
- F1 is reported per dataset; the benign corpus only yields an FPR (no positives).
