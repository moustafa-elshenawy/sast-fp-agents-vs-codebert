"""Cheap shortcut baselines on the masked dataset. NO CodeBERT, no GPU.
Purpose: how much of the label can be predicted from things that are NOT
real understanding of the code (tool counts, lengths, rule names, template wording)?
Anything a model trained on these does well, CodeBERT could also learn as a shortcut.

Usage: python3 scripts/baselines.py --csv ~/sifting-noise/work/dataset.csv
Needs: pip install scikit-learn pandas numpy
Metrics are out-of-fold (every case is scored by a model that never saw it).
"""
import argparse
import numpy as np
import pandas as pd
from scipy.sparse import hstack, csr_matrix
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold, GroupKFold
from sklearn.metrics import roc_auc_score, accuracy_score

ap = argparse.ArgumentParser()
ap.add_argument("--csv", required=True)
ap.add_argument("--folds", type=int, default=5)
ap.add_argument("--seed", type=int, default=0)
ap.add_argument("--keep-tp", type=float, default=0.7775,
                help="TP retention for the matched operating point (SWE-agent+Claude kept 77.75%%)")
a = ap.parse_args()

df = pd.read_csv(a.csv, keep_default_na=False)
df = df[df["has_code"].astype(str).str.lower() == "true"].reset_index(drop=True)
y = (df["label"] == "TP").astype(int).values
print(f"{len(df)} cases, {y.sum()} TP, {(1-y).sum()} FP, chance accuracy {max(y.mean(),1-y.mean()):.3f}\n")

# ---- feature builders (each returns train/test matrices; fit on train only) ----
TOOLS = ["CodeQL", "Semgrep", "Joern", "Sonarqube"]
def numeric(d, with_len):
    cols = {t: d["tools"].str.contains(t).astype(float) for t in TOOLS}
    cols["n_tools"] = d["n_tools"].astype(float)
    if with_len:
        cols["n_findings"] = d["n_findings"].astype(float)
        cols["n_code_lines"] = d["n_code_lines"].astype(float)
        cols["n_window_lines"] = d["n_window_lines"].astype(float)
        cols["alert_chars"] = d["alert_text"].str.len().astype(float)
        cols["window_chars"] = d["code_window"].str.len().astype(float)
    X = pd.DataFrame(cols).values
    return X

def make(kind):
    def f(tr, te):
        if kind in ("tools", "tools+lengths"):
            Xtr, Xte = numeric(tr, kind == "tools+lengths"), numeric(te, kind == "tools+lengths")
            mu, sd = Xtr.mean(0), Xtr.std(0) + 1e-9
            return (Xtr - mu) / sd, (Xte - mu) / sd
        txt = {"alert text": "alert_text", "code window": "code_window"}
        parts_tr, parts_te = [], []
        cols = ["alert_text", "code_window"] if kind == "alert + code" else [txt[kind]]
        for c in cols:
            v = TfidfVectorizer(token_pattern=r"[A-Za-z_][A-Za-z0-9_]+", ngram_range=(1, 2),
                                min_df=3, sublinear_tf=True)
            parts_tr.append(v.fit_transform(tr[c])); parts_te.append(v.transform(te[c]))
        return hstack(parts_tr).tocsr(), hstack(parts_te).tocsr()
    return f

def op_point(y_true, score, keep_tp):
    """Residual FP pass-through when the threshold keeps `keep_tp` of the TPs."""
    thr = np.quantile(score[y_true == 1], 1 - keep_tp)
    passed = (score[y_true == 0] >= thr).mean()
    return passed

def run(kind, splitter, groups=None):
    oof = np.zeros(len(df))
    for tr_i, te_i in splitter.split(df, y, groups):
        tr, te = df.iloc[tr_i], df.iloc[te_i]
        Xtr, Xte = make(kind)(tr, te)
        m = LogisticRegression(max_iter=2000, C=1.0)
        m.fit(Xtr, y[tr_i]); oof[te_i] = m.predict_proba(Xte)[:, 1]
    return oof

kinds = ["tools", "tools+lengths", "alert text", "code window", "alert + code"]
skf = StratifiedKFold(a.folds, shuffle=True, random_state=a.seed)
print("A) random 5-fold (test cases have look-alike siblings in training)")
print(f"{'features':16s} {'AUC':>6s} {'acc':>6s}  FP pass-through at {a.keep_tp:.1%} TP kept")
for k in kinds:
    o = run(k, skf)
    print(f"{k:16s} {roc_auc_score(y,o):6.3f} {accuracy_score(y,o>=.5):6.3f}  {op_point(y,o,a.keep_tp):.3f}")

print("\nB) leave-one-category-out (whole CWE family unseen in training)")
g = df["category"].values
gkf = GroupKFold(n_splits=len(set(g)))
print(f"{'features':16s} {'AUC':>6s} {'acc':>6s}  FP pass-through at {a.keep_tp:.1%} TP kept")
for k in kinds:
    o = run(k, gkf, g)
    print(f"{k:16s} {roc_auc_score(y,o):6.3f} {accuracy_score(y,o>=.5):6.3f}  {op_point(y,o,a.keep_tp):.3f}")

print("\nReference (base paper, SWE-agent + Claude Sonnet 4): FP pass-through about 0.064 "
      "(83 of 1,303) with 77.75% of TPs kept.")
print("These baselines are shortcut checks, not the comparison. Read AUC first: near 0.5 = no shortcut signal.")
