"""Dynamic int8 quantization of the exported PIGuard ONNX, to see whether it can ship
at a reasonable size without wrecking accuracy. Output: model_quantized.onnx."""
from pathlib import Path
from onnxruntime.quantization import quantize_dynamic, QuantType

HERE = Path(__file__).resolve().parent
REPO_ROOT = next(p for p in HERE.parents if (p / "AgentGuard.slnx").exists())
MODEL_DIR = REPO_ROOT / "eng" / "models" / "piguard"
src = MODEL_DIR / "model.onnx"
dst = MODEL_DIR / "model_quantized.onnx"

quantize_dynamic(str(src), str(dst), weight_type=QuantType.QInt8)
print(f"fp32 : {src.stat().st_size/1e6:7.1f} MB")
print(f"int8 : {dst.stat().st_size/1e6:7.1f} MB")
