#!/bin/bash
# Downloads the PIGuard ONNX prompt-injection model + DeBERTa v3 tokenizer.
#
# PIGuard (leolee99/PIGuard, ACL 2025, MIT) ships only PyTorch weights upstream, so AgentGuard
# distributes an ONNX export (produced by eng/piguard-eval/export_onnx.py). The SentencePiece
# tokenizer is the stock microsoft/deberta-v3-base spm.model (PIGuard's own spm.model on HF is an
# unmaterialized Git LFS pointer).
#
# Usage:
#   ./eng/download-piguard-model.sh [output-dir]
#
# Default output directory: ./models/piguard
#
# After downloading, set environment variables for E2E tests (absolute paths printed at end).

set -euo pipefail

# published ONNX export (derivative of leolee99/PIGuard, MIT). Defaults to the fp16 build
# (~369 MB, numerically identical to fp32). For the full fp32 model set
# PIGUARD_ONNX_URL=https://huggingface.co/filip-w/PIGuard-onnx/resolve/main/model.onnx
PIGUARD_REPO="${PIGUARD_REPO:-filip-w/PIGuard-onnx}"
PIGUARD_ONNX_URL="${PIGUARD_ONNX_URL:-https://huggingface.co/${PIGUARD_REPO}/resolve/main/model_fp16.onnx}"

# the SentencePiece tokenizer (deberta-v3-base spm.model) is mirrored in the same repo
SPM_URL="${SPM_URL:-https://huggingface.co/${PIGUARD_REPO}/resolve/main/spm.model}"

OUTPUT_DIR="${1:-./models/piguard}"
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"

echo "Downloading PIGuard model to $OUTPUT_DIR..."
echo ""

# model.onnx
if [ -f "$OUTPUT_DIR/model.onnx" ]; then
    echo "[skip] model.onnx already exists"
elif [ -z "$PIGUARD_ONNX_URL" ]; then
    echo "[error] PIGUARD_ONNX_URL is not set and no published default is configured yet."
    echo "        Set it to the hosted ONNX export, e.g.:"
    echo "          PIGUARD_ONNX_URL=https://huggingface.co/<owner>/PIGuard-onnx/resolve/main/model.onnx \\"
    echo "            ./eng/download-piguard-model.sh"
    echo "        Or export the model locally with eng/piguard-eval/export_onnx.py."
    exit 1
else
    echo "[download] model.onnx ..."
    curl -L --progress-bar "$PIGUARD_ONNX_URL" -o "$OUTPUT_DIR/model.onnx"
fi

# spm.model (DeBERTa v3 SentencePiece tokenizer)
if [ -f "$OUTPUT_DIR/spm.model" ]; then
    echo "[skip] spm.model already exists"
else
    echo "[download] spm.model (deberta-v3-base) ..."
    curl -L --progress-bar "$SPM_URL" -o "$OUTPUT_DIR/spm.model"
fi

echo ""
echo "Done. For E2E tests:"
echo "  export AGENTGUARD_PIGUARD_ONNX_MODEL_PATH=\"$OUTPUT_DIR/model.onnx\""
echo "  export AGENTGUARD_PIGUARD_TOKENIZER_PATH=\"$OUTPUT_DIR/spm.model\""
