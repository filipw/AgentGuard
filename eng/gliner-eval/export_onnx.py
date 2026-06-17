"""Export a GLiNER span NER model to ONNX and dump ground-truth fixtures for C# parity.

GLiNER (urchade/gliner_multi_pii-v1, mDeBERTa-v3 backbone, Apache-2.0) is a zero-shot span
NER model: the entity-type labels are part of the runtime input, not a frozen taxonomy. The
word-level input is

    [ENT] label1 [ENT] label2 ... [ENT] labelN [SEP] word1 word2 ... wordM

subword-tokenized (is_split_into_words) into

    [CLS] <prompt subwords> <text subwords> [SEP]

with a `words_mask` marking the first subword of each TEXT word (1-indexed, prompt/special -> 0).
The span model enumerates every (start, start+w) word span up to max_width and scores it against
every label, emitting logits[batch, num_words(L), max_width(K), num_classes(C)]. Decoding =
sigmoid -> threshold -> flat greedy non-overlap, then map word spans back to char offsets.

Unlike Opir/PIGuard there is NO frozen prefix: the C# side reproduces the input assembly and the
flat-greedy decode at inference time. This script is the authoritative source for that reproduction:
it exports the graph, writes a C#-facing config.json (special-token ids + max_width), and dumps a
fixtures.json (collated tensors + raw logits + library-decoded spans) the C# Gate 2/3 probe asserts
against id-for-id and score-for-score.

Output: eng/models/gliner/ (model.onnx, spm.model, config.json, fixtures.json, gliner native files).
"""
import json
import shutil
from pathlib import Path

import numpy as np
import onnxruntime as ort
import torch
from gliner import GLiNER
from huggingface_hub import hf_hub_download

HERE = Path(__file__).resolve().parent
REPO_ROOT = next(p for p in HERE.parents if (p / "AgentGuard.slnx").exists())
OUT_DIR = REPO_ROOT / "eng" / "models" / "gliner"
OUT_DIR.mkdir(parents=True, exist_ok=True)
ONNX_PATH = OUT_DIR / "model.onnx"

MODEL_ID = "urchade/gliner_multi_pii-v1"
SPM_SOURCE = "microsoft/mdeberta-v3-base"  # backbone tokenizer (250k multilingual spm)

# the C#-side prompt labels (lowercase) the recognizer maps to PERSON/LOCATION/ORGANIZATION/DATE_TIME
LABELS = ["person", "location", "organization", "date"]

# multilingual probes used for both the fixtures (Gate 2/3) and a smoke check. Latin + non-ASCII
# Latin (de) + Cyrillic (ru) + Arabic (ar) + CJK (zh) exercise tokenizer parity across scripts.
PROBES = [
    "Contact Jane Doe in Berlin at ACME Corp on March 3rd.",
    "Kontaktieren Sie Herrn Klaus Müller in München bei der Siemens AG am 5. Mai.",
    "Иван Петров живёт в Москве и работает в компании Газпром.",
    "اتصل بأحمد حسن في القاهرة لدى شركة أرامكو يوم الإثنين.",
    "联系北京华为公司的张伟，时间是十月一日。",
]


def main():
    print(f"loading {MODEL_ID} ...")
    model = GLiNER.from_pretrained(MODEL_ID)
    model.eval()

    cfg = model.config
    proc = model.data_processor
    tok = proc.transformer_tokenizer
    ent_token = getattr(cfg, "ent_token", "[ENT]")
    sep_token = getattr(cfg, "sep_token", "[SEP]")
    max_width = int(cfg.max_width)
    print(f"  model class: {model.__class__.__name__}")
    print(f"  backbone: {getattr(cfg, 'model_name', '?')}  max_width={max_width}")
    print(f"  ent_token={ent_token!r} sep_token={sep_token!r}")

    ent_id = tok.convert_tokens_to_ids(ent_token)
    sep_tok_id = tok.convert_tokens_to_ids(sep_token)
    cls_id = tok.cls_token_id
    sep_id = tok.sep_token_id
    pad_id = tok.pad_token_id
    print(f"  ids: ent={ent_id} sep_token={sep_tok_id} cls={cls_id} sep={sep_id} pad={pad_id}")

    # ---- export ----
    print("exporting ONNX (opset 19) ...")
    paths = model.export_to_onnx(str(OUT_DIR), onnx_filename="model.onnx", opset=19)
    print(f"  wrote {ONNX_PATH} ({ONNX_PATH.stat().st_size/1e6:.1f} MB)")

    sess = ort.InferenceSession(str(ONNX_PATH))
    print("  ONNX inputs:")
    for i in sess.get_inputs():
        print(f"    {i.name:16s} {i.type} {i.shape}")
    print("  ONNX outputs:")
    for o in sess.get_outputs():
        print(f"    {o.name:16s} {o.type} {o.shape}")
    onnx_input_names = [i.name for i in sess.get_inputs()]

    # ---- C#-facing config.json ----
    config = {
        "model_id": MODEL_ID,
        "backbone": SPM_SOURCE,
        "model_type": "span",
        "labels": LABELS,
        "max_width": max_width,
        "ent_token": ent_token,
        "sep_token": sep_token,
        "ent_token_id": int(ent_id),
        "sep_token_id": int(sep_tok_id),
        "cls_id": int(cls_id),
        "sep_id": int(sep_id),
        "pad_id": int(pad_id),
        "onnx_input_names": onnx_input_names,
        "words_splitter_regex": r"\w+(?:[-_]\w+)*|\S",
        "default_threshold": 0.5,
    }
    (OUT_DIR / "config.json").write_text(json.dumps(config, indent=2, ensure_ascii=False))
    print(f"  wrote config.json")

    # backbone spm for the C# tokenizer (same mdeberta spm Opir uses)
    spm_src = hf_hub_download(SPM_SOURCE, "spm.model")
    shutil.copy(spm_src, OUT_DIR / "spm.model")
    print(f"  copied spm.model ({(OUT_DIR / 'spm.model').stat().st_size/1e6:.1f} MB)")

    # ---- fixtures: collated tensors + raw logits + library-decoded spans ----
    print("\nbuilding parity fixtures ...")
    fixtures = []
    for text in PROBES:
        prepared = model.prepare_batch([text], LABELS)
        collator = model.create_collator()
        batch = model.collate_batch(prepared["input_x"], prepared["entity_types"], collator)

        feeds = {}
        for name in onnx_input_names:
            t = batch[name]
            arr = t.numpy() if isinstance(t, torch.Tensor) else np.asarray(t)
            feeds[name] = arr.astype(np.int64) if arr.dtype != np.bool_ else arr
        logits = sess.run(None, feeds)[0]  # [B, L, K, C]

        # ground-truth decoded spans (char offsets) from the library
        gt = model.predict_entities(text, LABELS, threshold=0.5, flat_ner=True)

        b0 = {
            "text": text,
            "labels": LABELS,
            "tokens": prepared["tokens"][0],
            "start_token_map": prepared["start_token_map"][0],
            "end_token_map": prepared["end_token_map"][0],
            "input_ids": feeds["input_ids"][0].tolist(),
            "attention_mask": feeds["attention_mask"][0].tolist(),
            "words_mask": feeds["words_mask"][0].tolist(),
            "text_lengths": np.asarray(batch["text_lengths"])[0].tolist(),
            "span_idx": feeds["span_idx"][0].tolist(),
            "span_mask": np.asarray(feeds["span_mask"][0]).astype(int).tolist(),
            "logits_shape": list(logits.shape),
            "logits": np.round(logits[0], 5).tolist(),
            "decoded": [
                {"start": e["start"], "end": e["end"], "label": e["label"],
                 "score": round(float(e["score"]), 5), "text": e["text"]}
                for e in gt
            ],
        }
        fixtures.append(b0)
        print(f"  [{text[:40]!r:44}] L={b0['text_lengths']} spans={len(b0['span_idx'])} "
              f"logits={b0['logits_shape']} entities={len(gt)}")
        for e in gt:
            print(f"      {e['label']:14s} {e['score']:.3f}  {e['text']!r}")

    (OUT_DIR / "fixtures.json").write_text(json.dumps(fixtures, indent=2, ensure_ascii=False))
    print(f"\n  wrote fixtures.json ({len(fixtures)} probes)")
    print("\nGate 1 done. Signature + decode confirmed; fixtures ready for C# Gate 2/3.")


if __name__ == "__main__":
    main()
