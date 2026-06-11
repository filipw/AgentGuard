from pathlib import Path
import onnx
from onnxconverter_common import float16
HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p / "AgentGuard.slnx").exists())
MD = ROOT / "eng" / "models" / "piguard"
m = onnx.load(str(MD / "model.onnx"))
m16 = float16.convert_float_to_float16(m, keep_io_types=True)
onnx.save(m16, str(MD / "model_fp16.onnx"))
print("fp16:", (MD/"model_fp16.onnx").stat().st_size/1e6, "MB")
