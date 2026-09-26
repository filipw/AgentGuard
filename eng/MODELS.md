# ONNX models for AgentGuard's gated tests

AgentGuard's ONNX guardrail rules (`AgentGuard.Onnx`) are thin adapters over the
[Kyoto](https://github.com/filipw/kyoto) classifier engine, which owns all ONNX model tooling
(conversion, evaluation, benchmarks, and the download/bootstrap scripts).

The **bundled Defender** prompt-injection model ships inside the Kyoto NuGet package and is copied
next to your app automatically - no download needed for the default `BlockPromptInjectionWithDefender()`.

The **optional BYO models** (PIGuard, Opir, GLiNER NER, generic DeBERTa) used by the gated E2E tests
and ONNX/PII samples are fetched from Hugging Face via Kyoto's bootstrap. From a sibling checkout of
the Kyoto repo:

```bash
cd ../kyoto
./bootstrap-models.sh                 # all models (~1.9 GB), or a subset: gliner, opir, piguard, deberta
source ./models/env.sh                # exports KYOTO_*_PATH and AGENTGUARD_*_PATH
cd ../AgentGuard && dotnet test AgentGuard.slnx
```

Each model lands in `../kyoto/models/<name>/` (`gliner`, `opir-multilang`, `piguard`,
`deberta-v3-prompt-injection`); a model already on disk is skipped, and `MODELS_DIR=...` changes the
target directory. For PIGuard, Opir and GLiNER the bootstrap downloads the fp16 export and saves it as
`model.onnx`.

The env file exports both the `KYOTO_*_PATH` variables (Kyoto's own gated tests) and the
`AGENTGUARD_*_PATH` variables this repo's E2E fixtures read, so one `source` un-gates both suites.
To use a model in your own app, point the rule's options (`ModelPath` and `TokenizerPath`, plus
`PrefixPath` for Opir or `ConfigPath` for GLiNER) at the downloaded files.

Published model exports (each repo has an fp16 `model_fp16.onnx` and an fp32 `model.onnx`):
- Defender (bundled): fine-tuned MiniLM-L6 multi-head (in the Kyoto package)
- PIGuard injection: https://huggingface.co/filip-w/PIGuard-onnx (plus `spm.model`)
- Opir multilingual content safety: https://huggingface.co/filip-w/opir-multilang-onnx (plus `spm.model`, `prefix.json`)
- GLiNER multilingual PII NER: https://huggingface.co/filip-w/gliner-multi-pii-onnx (plus `spm.model`, `config.json`)

The generic DeBERTa rule (`BlockPromptInjectionWithDeberta()`) has no AgentGuard-distributed export:
the bootstrap's `deberta` model is `model.onnx` and `spm.model` from the `onnx/` folder of
https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2.
