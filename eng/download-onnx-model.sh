#!/bin/bash
# Downloads the ONNX prompt injection model from HuggingFace.
# Model: protectai/deberta-v3-base-prompt-injection-v2
# Files: model.onnx (~370MB) + spm.model (tokenizer, ~2MB)
#
# Usage:
#   ./eng/download-onnx-model.sh [output-dir]
#
# Default output directory: ./models/deberta-v3-prompt-injection
#
# After downloading, set environment variables for E2E tests (absolute paths printed at end).

set -euo pipefail

OUTPUT_DIR="${1:-./models/deberta-v3-prompt-injection}"
BASE_URL="https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2/resolve/main/onnx"

mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"

echo "Downloading ONNX prompt injection model to $OUTPUT_DIR..."
echo ""

# Download model.onnx
if [ -f "$OUTPUT_DIR/model.onnx" ]; then
    echo "[skip] model.onnx already exists"
else
    echo "[download] model.onnx (~370MB)..."
    curl -L --progress-bar "$BASE_URL/model.onnx" -o "$OUTPUT_DIR/model.onnx"
fi

# Download spm.model (SentencePiece tokenizer)
if [ -f "$OUTPUT_DIR/spm.model" ]; then
    echo "[skip] spm.model already exists"
else
    echo "[download] spm.model..."
    curl -L --progress-bar "$BASE_URL/spm.model" -o "$OUTPUT_DIR/spm.model"
fi

echo ""
echo "Done. Model files:"
ls -lh "$OUTPUT_DIR"/model.onnx "$OUTPUT_DIR"/spm.model
echo ""
echo "To run ONNX E2E tests:"
echo "  export AGENTGUARD_ONNX_MODEL_PATH=$OUTPUT_DIR/model.onnx"
echo "  export AGENTGUARD_ONNX_TOKENIZER_PATH=$OUTPUT_DIR/spm.model"
echo "  dotnet test tests/AgentGuard.E2E.Tests --filter 'FullyQualifiedName~Onnx'"
