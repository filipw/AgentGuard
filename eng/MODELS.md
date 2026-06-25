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
./bootstrap-models.sh                 # all models (~1.9 GB), or e.g. ./bootstrap-models.sh gliner opir
source ./models/env.sh                # exports KYOTO_*_PATH and AGENTGUARD_*_PATH
cd ../AgentGuard && dotnet test AgentGuard.slnx
```

The env file exports both the `KYOTO_*_PATH` variables (Kyoto's own gated tests) and the
`AGENTGUARD_*_PATH` variables this repo's E2E fixtures read, so one `source` un-gates both suites.

Published model exports:
- Defender (bundled): fine-tuned MiniLM-L6 multi-head (in the Kyoto package)
- PIGuard injection: https://huggingface.co/filip-w/PIGuard-onnx
- Opir multilingual content safety: https://huggingface.co/filip-w/opir-multilang-onnx
- GLiNER multilingual PII NER: https://huggingface.co/filip-w/gliner-multi-pii-onnx
