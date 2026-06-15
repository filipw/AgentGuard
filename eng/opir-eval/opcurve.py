"""Operating-point comparison on content-safety / multilingual sets: score Opir
P(unsafe) and Azure max-severity once each, then sweep thresholds offline
(apples-to-apples). Azure costs 1 billed record per text.

Usage:
  python opcurve.py                                   # English content-safety sets
  python opcurve.py --multilingual --model knowledgator/opir-multitask-multilang-v1.0
"""
import argparse
import eval

ap = argparse.ArgumentParser()
ap.add_argument("--model", default=eval.DEFAULT_MODEL)
ap.add_argument("--multilingual", action="store_true")
ap.add_argument("--langs", default="de,es,ru,ar,zh,hi")
ap.add_argument("--per-class", type=int, default=25)
ap.add_argument("--no-azure", action="store_true", help="Opir threshold sweep only (free).")
args = ap.parse_args()

if args.multilingual:
    sets = eval.load_multilingual_toxicity_sets(
        [s.strip() for s in args.langs.split(",") if s.strip()], args.per_class)
else:
    sets = eval.load_content_safety_sets(args.per_class)

opir = eval.Opir(args.model, threshold=0.5, device="cpu",
                 unsafe_labels=tuple(s.strip() for s in eval.CONTENT_UNSAFE_LABELS.split(",")),
                 safe_labels=("safe and benign",))
az = None if args.no_azure else eval.Azure(threshold=2)

for name, _, rows in sets:
    texts = [t for t, _ in rows]
    labels = [l for _, l in rows]
    oprobs = opir.unsafe_probs(texts)
    asev = [az.severity(t) for t in texts] if az else None
    print(f"\n{name}  (n={len(rows)})")
    if az:
        print("  Opir P(unsafe)        |  Azure max-severity")
        print(f"  {'thr':>4} {'rec':>6} {'FPR':>6}   |  {'sev>=':>5} {'rec':>6} {'FPR':>6}")
        for thr, sev in [(0.5, 2), (0.8, 4), (0.9, 6)]:
            _, _, orec, ofpr = eval.metrics(labels, [p >= thr for p in oprobs])
            _, _, arec, afpr = eval.metrics(labels, [s >= sev for s in asev])
            print(f"  {thr:>4.2f} {orec*100:5.0f}% {ofpr*100:5.0f}%   |  "
                  f"{sev:>5} {arec*100:5.0f}% {afpr*100:5.0f}%")
    else:
        print(f"  {'thr':>4} {'rec':>6} {'FPR':>6}")
        for thr in [0.5, 0.7, 0.8, 0.9]:
            _, _, orec, ofpr = eval.metrics(labels, [p >= thr for p in oprobs])
            print(f"  {thr:>4.2f} {orec*100:5.0f}% {ofpr*100:5.0f}%")
print("\nOPCURVE-DONE")
