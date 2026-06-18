"""fp16 conversion of the GLiNER span NER ONNX export.

Same realign-Cast playbook as eng/opir-eval/fp16_onnx.py: onnxconverter_common's float16 pass
relabels tensor types to fp16 but leaves some pre-existing Cast nodes' `to` attribute stale
(int64 -> FLOAT casts on input_ids / words_mask / span_idx, plus casts inside the DeBERTa
control-flow If subgraphs and the LSTM pack/pad path). The output is then declared fp16 while the
Cast still says `to=FLOAT`, and ORT rejects the mismatch. We run the plain conversion, then align
every Cast node's `to` with the output type the converter actually declared, recursing into
If/Loop/Scan subgraphs. Fast, deterministic, preserves the size win (~1.16 GB fp32 -> ~580 MB fp16).

Validation: fp16 vs fp32 max |delta sigmoid(logit)| over all enumerated spans, replaying the exact
collated tensors captured in fixtures.json (so we don't reload the 1.1 GB PyTorch model).
"""
import json
import sys
from pathlib import Path

import numpy as np
import onnx
import onnxruntime as ort
from onnxconverter_common import float16

HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p / "AgentGuard.slnx").exists())
MD = ROOT / "eng" / "models" / "gliner"
src = MD / "model.onnx"
dst = MD / "model_fp16.onnx"

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

sess32 = ort.InferenceSession(str(src))
sess16 = ort.InferenceSession(str(dst))
print("loaded OK in ORT")

fixtures = json.loads((MD / "fixtures.json").read_text())


def feeds_for(fx):
    seq = len(fx["input_ids"])
    num_spans = len(fx["span_idx"])
    return {
        "input_ids": np.asarray([fx["input_ids"]], dtype=np.int64),
        "attention_mask": np.asarray([fx["attention_mask"]], dtype=np.int64),
        "words_mask": np.asarray([fx["words_mask"]], dtype=np.int64),
        "text_lengths": np.asarray([fx["text_lengths"]], dtype=np.int64),
        "span_idx": np.asarray([fx["span_idx"]], dtype=np.int64),
        "span_mask": np.asarray([fx["span_mask"]], dtype=bool),
    }


def sigmoid(x):
    return 1.0 / (1.0 + np.exp(-x))


worst = 0.0
print("\n  max|dP|   text")
for fx in fixtures:
    feeds = feeds_for(fx)
    a = sigmoid(sess32.run(None, feeds)[0].astype(np.float64))
    b = sigmoid(sess16.run(None, feeds)[0].astype(np.float64))
    d = float(np.max(np.abs(a - b)))
    worst = max(worst, d)
    print(f"  {d:.4f}   {fx['text'][:48]!r}")
ok = worst < 0.02
print(f"\nmax |delta P(span)| = {worst:.4f}  ->  {'OK' if ok else 'CHECK'}")
sys.exit(0 if ok else 1)
