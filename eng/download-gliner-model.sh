#!/bin/bash
# Downloads the GLiNER span NER ONNX model + mDeBERTa-v3 tokenizer + config for AgentGuard.Pii
# Stage 3 (offline PERSON / LOCATION / ORGANIZATION / DATE_TIME detection).
#
# GLiNER (urchade/gliner_multi_pii-v1, mDeBERTa-v3 backbone, Apache-2.0) ships only PyTorch weights
# upstream, so AgentGuard distributes an ONNX export (produced by eng/gliner-eval/export_onnx.py).
# GLiNER is zero-shot: the entity labels are part of the runtime input, NOT a frozen taxonomy, so
# there is no prefix.json - instead config.json carries the special-token ids and max span width the
# C# recognizer needs to assemble the input. The SentencePiece tokenizer is the stock
# mdeberta-v3-base spm.model (the same one Opir uses).
#
# Usage:
#   ./eng/download-gliner-model.sh [output-dir]
#
# Default output directory: ./models/gliner
#
# Defaults to the fp16 build (~580 MB, max delta P(span) 0.0043 vs fp32). For the full fp32 model set
#   GLINER_ONNX_URL=https://huggingface.co/filip-w/gliner-multi-pii-onnx/resolve/main/model.onnx
#
# After downloading, set environment variables for E2E tests (absolute paths printed at end).

set -euo pipefail

GLINER_REPO="${GLINER_REPO:-filip-w/gliner-multi-pii-onnx}"
GLINER_ONNX_URL="${GLINER_ONNX_URL:-https://huggingface.co/${GLINER_REPO}/resolve/main/model_fp16.onnx}"
SPM_URL="${SPM_URL:-https://huggingface.co/${GLINER_REPO}/resolve/main/spm.model}"
CONFIG_URL="${CONFIG_URL:-https://huggingface.co/${GLINER_REPO}/resolve/main/config.json}"

OUTPUT_DIR="${1:-./models/gliner}"
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"

echo "Downloading GLiNER NER model to $OUTPUT_DIR..."
echo ""

# model.onnx (fp16 by default)
if [ -f "$OUTPUT_DIR/model.onnx" ]; then
    echo "[skip] model.onnx already exists"
else
    echo "[download] model.onnx ..."
    curl -L --progress-bar "$GLINER_ONNX_URL" -o "$OUTPUT_DIR/model.onnx"
fi

# spm.model (mDeBERTa-v3-base SentencePiece tokenizer)
if [ -f "$OUTPUT_DIR/spm.model" ]; then
    echo "[skip] spm.model already exists"
else
    echo "[download] spm.model (mdeberta-v3-base) ..."
    curl -L --progress-bar "$SPM_URL" -o "$OUTPUT_DIR/spm.model"
fi

# config.json (special-token ids + max span width the C# recognizer assembles the input from)
if [ -f "$OUTPUT_DIR/config.json" ]; then
    echo "[skip] config.json already exists"
else
    echo "[download] config.json ..."
    curl -L --progress-bar "$CONFIG_URL" -o "$OUTPUT_DIR/config.json"
fi

echo ""
echo "Done. For E2E tests:"
echo "  export AGENTGUARD_GLINER_ONNX_MODEL_PATH=\"$OUTPUT_DIR/model.onnx\""
echo "  export AGENTGUARD_GLINER_TOKENIZER_PATH=\"$OUTPUT_DIR/spm.model\""
echo "  export AGENTGUARD_GLINER_CONFIG_PATH=\"$OUTPUT_DIR/config.json\""
