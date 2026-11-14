"""Combine saved predictions from train_codebert.py and print the headline numbers.
Usage: python3 scripts/evaluate_runs.py --runs ~/sifting-noise/work/runs
Groups files preds_<inputs>_<random|loco>_*.csv. Pooled numbers mix folds
(different calibration), so per-fold / per-category AUC is printed too."""
import argparse, glob, os, re
import numpy as np, pandas as pd
from sklearn.metrics import roc_auc_score
ap = argparse.ArgumentParser()
ap.add_argument("--runs", required=True)
ap.add_argument("--keep-tp", type=float, default=0.7775)
a = ap.parse_args()

def passthrough(y, s, keep):
    thr = np.quantile(s[y == 1], 1 - keep)
    return float((s[y == 0] >= thr).mean())

groups = {}
for p in sorted(glob.glob(os.path.join(a.runs, "preds_*.csv"))):
    m = re.match(r"preds_(both|alert|code)_(random|loco)", os.path.basename(p))
    if m:
        groups.setdefault((m.group(1), m.group(2)), []).append(p)
if not groups:
    raise SystemExit("no prediction files found")
for (inp, fam), files in groups.items():
    d = pd.concat([pd.read_csv(f).assign(run=os.path.basename(f)[6:-4]) for f in files])
    y = (d["label"] == "TP").astype(int).values; s = d["score"].values
    print(f"\n=== inputs={inp}  split={fam}  runs={len(files)}  cases={len(d)} ===")
    print("pooled: AUC %.3f  acc %.3f  FP pass-through at %.1f%% TP kept: %.3f" %
          (roc_auc_score(y, s), ((s >= .5) == y).mean(), a.keep_tp * 100, passthrough(y, s, a.keep_tp)))
    rows = []
    for run, g in d.groupby("run"):
        yy = (g["label"] == "TP").astype(int).values
        if len(set(yy)) == 2:
            rows.append((run, len(g), roc_auc_score(yy, g["score"]), ((g["score"] >= .5) == yy).mean()))
    for run, n, auc, acc in rows:
        print(f"  {run:32s} n={n:4d}  AUC {auc:.3f}  acc {acc:.3f}")
    if rows:
        print("  mean per-run AUC %.3f" % np.mean([r[2] for r in rows]))
print("\nBaseline to beat: the word-count models in scripts/baselines.py; agent reference ~0.064 pass-through.")
