"""Gate 5 data prep: dump the exact balanced textdetox samples eval.py measured, so the C#
re-measure (eng/opir-csharp-eval) scores the same rows and its recall/FPR is directly
comparable to RESULTS.md section 3.

Mirrors eval.py::load_multilingual_toxicity_sets + _balanced (first `per_class` positives and
first `per_class` negatives in dataset order) for each language split.
"""
import json
from pathlib import Path

from datasets import load_dataset

HERE = Path(__file__).resolve().parent
REPO_ROOT = next(p for p in HERE.parents if (p / "AgentGuard.slnx").exists())
OUT = REPO_ROOT / "eng" / "models" / "opir-multilang" / "eval_multilingual.json"

LANGS = ["de", "es", "ru", "ar", "zh", "hi"]
PER_CLASS = 25


def balanced(rows, per_class):
    pos = [r for r in rows if r[1] == 1][:per_class]
    neg = [r for r in rows if r[1] == 0][:per_class]
    return pos + neg


def main():
    out = []
    for lang in LANGS:
        ds = load_dataset("textdetox/multilingual_toxicity_dataset", split=lang)
        rows = [(r["text"], 1 if str(r["toxic"]) in ("1", "1.0") else 0)
                for r in ds if (r.get("text") or "").strip()]
        for text, label in balanced(rows, PER_CLASS):
            out.append({"lang": lang, "text": text, "label": label})

    OUT.write_text(json.dumps(out, ensure_ascii=False, indent=0))
    n_pos = sum(1 for r in out if r["label"] == 1)
    print(f"wrote {OUT} ({len(out)} rows, {n_pos} toxic / {len(out) - n_pos} benign across {LANGS})")


if __name__ == "__main__":
    main()
