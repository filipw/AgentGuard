"""fp16 conversion of the Opir-multilang ONNX export.

Same realign-Cast playbook as eng/piguard-eval/fp16_onnx.py: onnxconverter_common's float16
pass relabels tensor types to fp16 but leaves some pre-existing Cast nodes' `to` attribute
stale (int64 -> FLOAT casts on input_ids / attention_mask, plus casts inside the DeBERTa
control-flow If subgraphs). The output is then declared fp16 while the Cast still says
`to=FLOAT`, and ORT rejects the mismatch. We run the plain conversion, then align every Cast
node's `to` with the output type the converter actually declared, recursing into If/Loop/Scan
subgraphs. Fast, deterministic, preserves the size win (~1.12 GB fp32 -> ~560 MB fp16).

Validation: fp16 vs fp32 P(unsafe) = max sigmoid over the 6 frozen harm labels, on
multilingual probes. Inputs are built exactly like the gliclass UniEncoder pipeline (frozen
label prefix + text via the HF tokenizer) so we don't need to reload the 1.1 GB PyTorch model.
"""
import json
import sys
from pathlib import Path

import numpy as np
import onnx
import onnxruntime as ort
from onnxconverter_common import float16
from transformers import AutoTokenizer

HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p / "AgentGuard.slnx").exists())
MD = ROOT / "eng" / "models" / "opir-multilang"
src = MD / "model.onnx"
dst = MD / "model_fp16.onnx"

MODEL_ID = "knowledgator/opir-multitask-multilang-v1.0"
UNSAFE = ["toxicity", "hate speech", "violence", "sexual content", "self-harm", "harassment"]
# must match export_onnx.py: a "safe and benign" sentinel is baked as label 0 for calibration and
# excluded from P(unsafe).
TAXONOMY = ["safe and benign"] + UNSAFE

m = onnx.load(str(src))
m16 = float16.convert_float_to_float16(m, keep_io_types=True)


def realign(graph, outer_types):
    """align each Cast's `to` with its declared output type; recurse into subgraphs."""
    types = dict(outer_types)
    for vi in list(graph.value_info) + list(graph.input) + list(graph.output):
        if vi.type.tensor_type.HasField("elem_type"):
            types[vi.name] = vi.type.tensor_type.elem_type
    fixed = 0
    for node in graph.node:
        if node.op_type == "Cast":
            ot = types.get(node.output[0])
            if ot is not None:
                for attr in node.attribute:
                    if attr.name == "to" and attr.i != ot:
                        attr.i = ot
                        fixed += 1
        for attr in node.attribute:
            if attr.type == onnx.AttributeProto.GRAPH:
                fixed += realign(attr.g, types)
            elif attr.type == onnx.AttributeProto.GRAPHS:
                for g in attr.graphs:
                    fixed += realign(g, types)
    return fixed


fixed = realign(m16.graph, {})
onnx.save(m16, str(dst))
print(f"fp16: {dst.stat().st_size/1e6:.1f} MB  (realigned {fixed} Cast 'to' attrs incl. subgraphs)")

# validate: must load + match fp32 P(unsafe)
sess_32 = ort.InferenceSession(str(src))
sess_16 = ort.InferenceSession(str(dst))
print("loaded OK in ORT")

tok = AutoTokenizer.from_pretrained(MODEL_ID)
PREFIX = "".join(f"<<LABEL>>{l}" for l in TAXONOMY) + "<<SEP>>"


UNSAFE_IDX = [TAXONOMY.index(l) for l in UNSAFE]  # exclude the safe sentinel from P(unsafe)


def punsafe(sess, text):
    enc = tok(PREFIX + text, return_tensors="np", truncation=True, max_length=512)
    logits = sess.run(None, {
        "input_ids": enc["input_ids"].astype(np.int64),
        "attention_mask": enc["attention_mask"].astype(np.int64),
    })[0][0].astype(np.float64)
    probs = 1.0 / (1.0 + np.exp(-logits))
    return float(probs[UNSAFE_IDX].max())


probes = [
    "Hello, how can I help you today?",
    "You are a worthless idiot and everyone hates you.",
    "Du bist ein hirnloser Vollidiot und solltest verschwinden.",
    "Eres un completo imbecil y no vales para nada.",
    "Ты тупой придурок и никому не нужен.",
    "أنت غبي جدا ولا تستحق الاحترام.",
    "你是个十足的白痴，没人喜欢你。",
    "तुम एक बेकार मूर्ख हो और किसी को तुम्हारी जरूरत नहीं है।",
    "The weather in Paris is lovely this time of year.",
]
print("\n  fp32     fp16     |delta|   text")
worst = 0.0
for t in probes:
    a, b = punsafe(sess_32, t), punsafe(sess_16, t)
    worst = max(worst, abs(a - b))
    print(f"  {a:.4f}   {b:.4f}   {abs(a-b):.4f}   {t[:45]!r}")
ok = worst < 0.02
print(f"\nmax |delta P(unsafe)| = {worst:.4f}  ->  {'OK' if ok else 'CHECK'}")
sys.exit(0 if ok else 1)
