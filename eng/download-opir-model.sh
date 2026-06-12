#!/bin/bash
# Downloads the Opir-multilang ONNX content-safety model + mDeBERTa-v3 tokenizer + label prefix.
#
# Opir-multilang (knowledgator/opir-multitask-multilang-v1.0, GLiClass uni-encoder over
# microsoft/mdeberta-v3-base, Apache-2.0) ships only PyTorch weights upstream, so AgentGuard
# distributes an ONNX export (produced by eng/opir-eval/export_onnx.py) with a FROZEN V1
# taxonomy baked into the graph. The SentencePiece tokenizer is the stock mdeberta-v3-base
# spm.model; prefix.json holds the precomputed label-prefix token ids the C# rule prepends.
#
# Usage:
#   ./eng/download-opir-model.sh [output-dir]
#
# Default output directory: ./models/opir-multilang
#
# Defaults to the fp16 build (~561 MB, numerically equivalent to fp32). For the full fp32 model set
#   OPIR_ONNX_URL=https://huggingface.co/filip-w/opir-multilang-onnx/resolve/main/model.onnx
#
# After downloading, set environment variables for E2E tests (absolute paths printed at end).

set -euo pipefail

OPIR_REPO="${OPIR_REPO:-filip-w/opir-multilang-onnx}"
OPIR_ONNX_URL="${OPIR_ONNX_URL:-https://huggingface.co/${OPIR_REPO}/resolve/main/model_fp16.onnx}"
SPM_URL="${SPM_URL:-https://huggingface.co/${OPIR_REPO}/resolve/main/spm.model}"
PREFIX_URL="${PREFIX_URL:-https://huggingface.co/${OPIR_REPO}/resolve/main/prefix.json}"

OUTPUT_DIR="${1:-./models/opir-multilang}"
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"

echo "Downloading Opir-multilang model to $OUTPUT_DIR..."
echo ""

# model.onnx (fp16 by default)
if [ -f "$OUTPUT_DIR/model.onnx" ]; then
    echo "[skip] model.onnx already exists"
else
    echo "[download] model.onnx ..."
    curl -L --progress-bar "$OPIR_ONNX_URL" -o "$OUTPUT_DIR/model.onnx"
fi

# spm.model (mDeBERTa-v3-base SentencePiece tokenizer)
if [ -f "$OUTPUT_DIR/spm.model" ]; then
    echo "[skip] spm.model already exists"
else
    echo "[download] spm.model (mdeberta-v3-base) ..."
    curl -L --progress-bar "$SPM_URL" -o "$OUTPUT_DIR/spm.model"
fi

# prefix.json (frozen taxonomy + precomputed label-prefix token ids)
if [ -f "$OUTPUT_DIR/prefix.json" ]; then
    echo "[skip] prefix.json already exists"
else
    echo "[download] prefix.json ..."
    curl -L --progress-bar "$PREFIX_URL" -o "$OUTPUT_DIR/prefix.json"
fi

echo ""
echo "Done. For E2E tests:"
echo "  export AGENTGUARD_OPIR_ONNX_MODEL_PATH=\"$OUTPUT_DIR/model.onnx\""
echo "  export AGENTGUARD_OPIR_TOKENIZER_PATH=\"$OUTPUT_DIR/spm.model\""
echo "  export AGENTGUARD_OPIR_PREFIX_PATH=\"$OUTPUT_DIR/prefix.json\""
