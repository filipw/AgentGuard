"""Gate 4: per-entity span precision/recall/F1 + threshold sweep for the GLiNER NER export.

Runs the real model (the same predict path the C# recognizer mirrors) over a held-out NER set and
reports span-level micro/per-type P/R/F1 across a threshold sweep, so the default NerThreshold is
picked from a curve rather than assumed. CoNLL-2003 validation (PER/LOC/ORG) is the clean default;
DATE_TIME is not in CoNLL and is validated qualitatively by the e2e tests + fixtures.

Usage:
    python eval.py [--limit N] [--split validation]

A span counts as a true positive when an exact (char-start, char-end, type) match exists in gold.
"""
import argparse
from collections import defaultdict

from datasets import load_dataset
from gliner import GLiNER

MODEL_ID = "urchade/gliner_multi_pii-v1"
# CoNLL tag id -> (gold type, gliner prompt label). CoNLL: 1/2 PER, 3/4 ORG, 5/6 LOC, 7/8 MISC.
CONLL = {1: "PER", 2: "PER", 3: "ORG", 4: "ORG", 5: "LOC", 6: "LOC"}
GOLD_TO_LABEL = {"PER": "person", "ORG": "organization", "LOC": "location"}
LABELS = ["person", "organization", "location"]
THRESHOLDS = [0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]


def gold_spans(tokens, tags):
    """reconstruct text (space-joined) and gold char spans from BIO-ish CoNLL tags."""
    text, spans, cur = "", [], None
    offsets = []
    for tok in tokens:
        if text:
            text += " "
        offsets.append(len(text))
        text += tok
    for i, tag in enumerate(tags):
        t = CONLL.get(tag)
        start = offsets[i]
        end = start + len(tokens[i])
        if t is None:
            if cur:
                spans.append(cur)
                cur = None
            continue
        # tags 1/3/5 are B-, 2/4/6 are I-; start a new span on B- or type change
        is_begin = tag in (1, 3, 5) or cur is None or cur[2] != t
        if is_begin:
            if cur:
                spans.append(cur)
            cur = [start, end, t]
        else:
            cur[1] = end
    if cur:
        spans.append(cur)
    return text, {(s, e, GOLD_TO_LABEL[t]) for s, e, t in spans}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=300)
    ap.add_argument("--split", default="validation")
    args = ap.parse_args()

    print(f"loading {MODEL_ID} ...")
    model = GLiNER.from_pretrained(MODEL_ID)
    model.eval()

    # the script-based loader is gone in recent `datasets`; use HF's auto-parquet conversion ref.
    ds = load_dataset("eriktks/conll2003", split=args.split, revision="refs/convert/parquet")
    rows = ds.select(range(min(args.limit, len(ds))))
    print(f"evaluating {len(rows)} sentences from conll2003/{args.split}\n")

    # tp/fp/fn per (threshold, type)
    stat = {th: defaultdict(lambda: [0, 0, 0]) for th in THRESHOLDS}
    for row in rows:
        text, gold = gold_spans(row["tokens"], row["ner_tags"])
        if not text.strip():
            continue
        for th in THRESHOLDS:
            preds = model.predict_entities(text, LABELS, threshold=th, flat_ner=True)
            pred = {(p["start"], p["end"], p["label"]) for p in preds}
            for typ in LABELS:
                g = {x for x in gold if x[2] == typ}
                pr = {x for x in pred if x[2] == typ}
                stat[th][typ][0] += len(g & pr)
                stat[th][typ][1] += len(pr - g)
                stat[th][typ][2] += len(g - pr)

    def prf(tp, fp, fn):
        p = tp / (tp + fp) if tp + fp else 0.0
        r = tp / (tp + fn) if tp + fn else 0.0
        f = 2 * p * r / (p + r) if p + r else 0.0
        return p, r, f

    print(f"{'thresh':>6} {'type':>13} {'P':>6} {'R':>6} {'F1':>6}")
    best = (0.0, -1.0)
    for th in THRESHOLDS:
        mtp = mfp = mfn = 0
        for typ in LABELS:
            tp, fp, fn = stat[th][typ]
            mtp += tp; mfp += fp; mfn += fn
            p, r, f = prf(tp, fp, fn)
            print(f"{th:>6.2f} {typ:>13} {p:>6.3f} {r:>6.3f} {f:>6.3f}")
        p, r, f = prf(mtp, mfp, mfn)
        print(f"{th:>6.2f} {'MICRO':>13} {p:>6.3f} {r:>6.3f} {f:>6.3f}\n")
        if f > best[1]:
            best = (th, f)
    print(f"best micro-F1 threshold: {best[0]:.2f} (F1={best[1]:.3f})")


if __name__ == "__main__":
    main()
