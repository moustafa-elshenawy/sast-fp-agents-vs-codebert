"""Train a small classifier on the saved CodeBERT embeddings and evaluate it
with the same splits as baselines.py: random 5-fold and leave-one-category-out.
Usage: python3 scripts/embed_eval.py --csv ~/sifting-noise/work/dataset.csv --emb ~/sifting-noise/work/emb/emb_both.npz
The regularisation strength is chosen by 3-fold CV inside each training set only."""
import argparse, warnings
warnings.filterwarnings("ignore")
import numpy as np, pandas as pd
from sklearn.linear_model import LogisticRegressionCV
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import roc_auc_score

ap = argparse.ArgumentParser()
ap.add_argument("--csv", required=True)
ap.add_argument("--emb", required=True)
ap.add_argument("--pool", choices=["mean", "cls"], default="mean")
ap.add_argument("--keep-tp", type=float, default=0.7775)
ap.add_argument("--seed", type=int, default=0)
a = ap.parse_args()

df = pd.read_csv(a.csv, keep_default_na=False)
df = df[df["has_code"].astype(str).str.lower() == "true"].reset_index(drop=True)
z = np.load(a.emb)
pos = {c: i for i, c in enumerate(z["case_id"])}
keep = df["case_id"].isin(pos).values
df = df[keep].reset_index(drop=True)
X = z[a.pool][[pos[c] for c in df["case_id"]]]
y = (df["label"] == "TP").astype(int).values
cat = df["category"].values
print(f"{len(df)} cases, features {X.shape[1]} ({a.pool}-pooled), {y.sum()} TP / {(1-y).sum()} FP\n")

def passthrough(yy, s, keep):
    thr = np.quantile(s[yy == 1], 1 - keep)
    return float((s[yy == 0] >= thr).mean())

def fit_predict(tr, te):
    sc = StandardScaler().fit(X[tr])
    m = LogisticRegressionCV(Cs=[1e-3, 1e-2, 1e-1, 1.0], cv=3, scoring="roc_auc", max_iter=3000)
    m.fit(sc.transform(X[tr]), y[tr])
    return m.predict_proba(sc.transform(X[te]))[:, 1]

def show(name, oof):
    print("%-28s AUC %.3f  acc %.3f  FP pass-through at %.1f%% TP kept: %.3f" %
          (name, roc_auc_score(y, oof), ((oof >= .5) == y).mean(), a.keep_tp * 100, passthrough(y, oof, a.keep_tp)))

oof = np.zeros(len(df))
for tr, te in StratifiedKFold(5, shuffle=True, random_state=a.seed).split(X, y):
    oof[te] = fit_predict(tr, te)
show("A) random 5-fold", oof)

oof2, per = np.zeros(len(df)), []
for c in sorted(set(cat)):
    te = np.where(cat == c)[0]; tr = np.where(cat != c)[0]
    oof2[te] = fit_predict(tr, te)
    if len(set(y[te])) == 2:
        per.append((c, len(te), roc_auc_score(y[te], oof2[te])))
show("B) leave-one-category-out", oof2)
print("\nper held-out category:")
for c, n, auc in per:
    print(f"  {c:14s} n={n:4d}  AUC {auc:.3f}")
print("\nCompare with scripts/baselines.py (word counts) and the agent reference ~0.064 pass-through.")
