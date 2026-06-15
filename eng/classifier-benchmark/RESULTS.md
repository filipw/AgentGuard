# Classifier benchmark results

Injection classifiers run as the real AgentGuard rules (`IGuardrailRule.EvaluateAsync`) on
held-out datasets. recall = % injection blocked, FPR = % benign blocked. Defender at its shipping
calibration (`main >= 0.75 AND aux < 0.64`, T=2.41). LLM = `LlmPromptInjectionRule` over three local
reasoning models (sequential, fails open on timeout): `gemma-4-26b-a4b-qat` (26B MoE, ~4B active),
`gemma-4-e2b` (2B dense Q8), and `qwen3-0.6b` (0.6B dense).

Sample: balanced 25/class per dataset (`--max-rows 25`), so treat deltas under ~10pp as noise.
Timing (the `time` column = wall-clock for the whole dataset, sequential) measured on an Apple M4 Pro.

## jackhhao/jailbreak-classification (test, held-out) - 50 rows

| classifier | prec | recall | F1 | FPR | time |
|---|---|---|---|---|---|
| regex-medium | 88% | 60% | 71% | 8.0% | 0s |
| regex-high | 88% | 60% | 71% | 8.0% | 0s |
| defender | 96% | 92% | 94% | 4.0% | 0s |
| llm (gemma 26B-a4b) | 100% | 96% | **98%** | 0.0% | 361s |
| llm (gemma 2B) | 92% | 92% | 92% | 8.0% | 332s |
| llm (qwen3 0.6B) | 67% | 32% | 43% | 16.0% | 74s |

## deepset/prompt-injections (test, held-out, German-heavy) - 50 rows

| classifier | prec | recall | F1 | FPR | time |
|---|---|---|---|---|---|
| regex-medium | 100% | 8% | 15% | 0.0% | 0s |
| regex-high | 100% | 8% | 15% | 0.0% | 0s |
| defender | 100% | 64% | 78% | 0.0% | 0s |
| llm (gemma 26B-a4b) | 100% | 68% | **81%** | 0.0% | 284s |
| llm (gemma 2B) | 100% | 44% | 61% | 0.0% | 272s |
| llm (qwen3 0.6B) | 100% | 16% | 28% | 0.0% | 51s |

## English customer-service benign corpus - 34 rows (FPR only)

| classifier | FPR | time |
|---|---|---|
| regex-medium | 0.0% | 0s |
| regex-high | 0.0% | 0s |
| defender | 14.7% | 0s |
| llm (gemma 26B-a4b) | 0.0% | 85s |
| llm (gemma 2B) | 2.9% | 168s |
| llm (qwen3 0.6B) | 2.9% | 33s |

## Reading

1. **LLM-as-judge quality scales hard with the model.** The capable `gemma-4-26b-a4b` tops both
   held-out sets (F1 98 / 81) at 0% FPR; the tiny `qwen3-0.6b` is far below even regex (F1 43 / 28,
   16% FPR on jackhhao). An LLM tier is only worth it with a capable model - a small one is not an
   automatic upgrade over the bundled Defender (F1 94 / 78); here it is much worse.
2. **Speed tracks active params, not total size.** `gemma-4-26b-a4b` is an MoE (~4B active) at
   ~6s/row; `qwen3-0.6b` is ~1.5s/row; the *dense* 2B (`gemma-4-e2b`) is also ~6s/row because it
   emits more reasoning tokens to reach an answer. So a small dense model buys neither the accuracy
   of the MoE nor a meaningful latency win.
3. **Defender is the strong fast default.** F1 94 on English jailbreaks, 78 on German injections,
   ~ms latency, bundled. Its one weak spot is benign-imperative FPR (14.7% on the customer-service
   corpus - the known "show me my orders" over-defense), where regex and the LLMs sit near 0%.
4. **Regex is high-precision, low-recall.** It rarely false-positives but misses most attacks, and
   collapses on non-English (deepset recall 8%). A cheap first-pass filter, not a standalone guard.
   Medium and High sensitivity tie on these sets.
5. **Complementary, not competing.** Cheap regex first, Defender for the common case, an LLM as an
   accurate (slow) backstop - which is the order the pipeline runs them (10 -> 11 -> 15).

Repro: `dotnet run -c Release -- --max-rows 25 [--llm-model <id>]` (see README). Larger `--max-rows`
tightens the estimates at the cost of more LLM time.
