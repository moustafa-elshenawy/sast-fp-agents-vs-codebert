"""Fine-tune CodeBERT to decide TP/FP from (scanner alert, code) for ONE split.

Why the input is built the way it is: most cases exceed CodeBERT's 512 tokens
(median ~1,050 for alert + code window). We give each part a fixed token budget
instead of cutting the end: alert lines are shortened and whole lines dropped
from the end; code is built by keeping the flagged lines first and then adding
neighbouring lines until the budget is full. Everything is counted and reported
by label so we can see whether the cutting itself could leak the label.

Examples (run from the repo folder):
  # 1) timing test only: a few cases, 1 epoch, prints an estimate for a full run
  python3 scripts/train_codebert.py --csv ~/sifting-noise/work/dataset.csv --split loco --heldout xss --timing
  # 2) one real run: random 5-fold, fold 0 (in-distribution)
  python3 scripts/train_codebert.py --csv ... --split random --fold 0
  # 3) the headline test: hold out one whole category
  python3 scripts/train_codebert.py --csv ... --split loco --heldout xss
  # ablations: --inputs code  /  --inputs alert  (shortcut controls)
Needs: pip install torch transformers scikit-learn pandas numpy
Fixed recipe (no tuning on test data): 3 epochs, lr 2e-5, effective batch 16.
"""
import argparse, json, os, time, random
import numpy as np
import pandas as pd
import torch
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import roc_auc_score
from transformers import AutoTokenizer, AutoModelForSequenceClassification, get_linear_schedule_with_warmup

ap = argparse.ArgumentParser()
ap.add_argument("--csv", required=True)
ap.add_argument("--out", default=os.path.expanduser("~/sifting-noise/work/runs"))
ap.add_argument("--model", default="microsoft/codebert-base")
ap.add_argument("--inputs", choices=["both", "alert", "code"], default="both")
ap.add_argument("--split", choices=["random", "loco"], required=True)
ap.add_argument("--folds", type=int, default=5)
ap.add_argument("--fold", type=int, default=0)
ap.add_argument("--heldout", default=None, help="category to hold out (loco)")
ap.add_argument("--alert-budget", type=int, default=None)
ap.add_argument("--code-budget", type=int, default=None)
ap.add_argument("--epochs", type=int, default=3)
ap.add_argument("--lr", type=float, default=2e-5)
ap.add_argument("--batch", type=int, default=4)
ap.add_argument("--accum", type=int, default=4)
ap.add_argument("--seed", type=int, default=0)
ap.add_argument("--keep-tp", type=float, default=0.7775)
ap.add_argument("--timing", action="store_true", help="tiny run + estimate for the full split")
ap.add_argument("--force", action="store_true", help="re-run even if predictions exist")
a = ap.parse_args()


random.seed(a.seed); np.random.seed(a.seed); torch.manual_seed(a.seed)
dev = torch.device("cuda" if torch.cuda.is_available() else
                   "mps" if getattr(torch.backends, "mps", None) and torch.backends.mps.is_available() else "cpu")

df = pd.read_csv(a.csv, keep_default_na=False)
df = df[df["has_code"].astype(str).str.lower() == "true"].reset_index(drop=True)
if "flag_lines" not in df.columns:
    raise SystemExit("dataset.csv has no flag_lines column: re-run the newest build_dataset.py first.")
y_all = (df["label"] == "TP").astype(int).values

# ---------------- split ----------------
if a.split == "random":
    skf = StratifiedKFold(a.folds, shuffle=True, random_state=a.seed)
    tr_idx, te_idx = list(skf.split(df, y_all))[a.fold]
    split_name = f"random{a.folds}_f{a.fold}"
else:
    cats = sorted(df["category"].unique())
    held = a.heldout or cats[a.fold]
    if held not in cats:
        raise SystemExit(f"unknown category {held!r}; choose from {cats}")
    te_idx = np.where(df["category"] == held)[0]
    tr_idx = np.where(df["category"] != held)[0]
    split_name = f"loco_{held}"
run_name = f"{a.inputs}_{split_name}"
os.makedirs(a.out, exist_ok=True)
pred_path = os.path.join(a.out, f"preds_{run_name}.csv")
if os.path.exists(pred_path) and not a.timing and not a.force:
    raise SystemExit(f"{pred_path} exists; use --force to redo it.")
print(f"run {run_name}: train {len(tr_idx)}, test {len(te_idx)}, device {dev}, "
      f"inputs {a.inputs}")

tok = AutoTokenizer.from_pretrained(a.model)

# ---------------- input building (shared with the embedding script) ----------------
from cb_inputs import encode_all, report
t0 = time.time()
enc_all, st = encode_all(df, tok, a.inputs, a.alert_budget, a.code_budget)
print("input building: %.0fs" % (time.time() - t0))
rep = report(st, df["label"].values)
print("input stats:", json.dumps(rep))

# ---------------- model ----------------
full_tr, full_te = len(tr_idx), len(te_idx)
if a.timing:
    rs = np.random.RandomState(0)
    tr_idx = rs.choice(tr_idx, min(64, len(tr_idx)), replace=False)
    te_idx = rs.choice(te_idx, min(48, len(te_idx)), replace=False)
    a.epochs = 1

def batches(idx, bs, shuffle):
    idx = list(idx)
    if shuffle:
        random.shuffle(idx)
    for i in range(0, len(idx), bs):
        chunk = idx[i:i + bs]
        L = max(len(enc_all[j]) for j in chunk)
        ids = torch.full((len(chunk), L), tok.pad_token_id, dtype=torch.long)
        att = torch.zeros((len(chunk), L), dtype=torch.long)
        for k, j in enumerate(chunk):
            n = len(enc_all[j]); ids[k, :n] = torch.tensor(enc_all[j]); att[k, :n] = 1
        yield chunk, ids.to(dev), att.to(dev), torch.tensor(y_all[chunk]).to(dev)

model = AutoModelForSequenceClassification.from_pretrained(a.model, num_labels=2).to(dev)
opt = torch.optim.AdamW(model.parameters(), lr=a.lr, weight_decay=0.01)
steps = max(1, (len(tr_idx) + a.batch * a.accum - 1) // (a.batch * a.accum)) * a.epochs
sched = get_linear_schedule_with_warmup(opt, int(0.1 * steps), steps)

t_train = time.time(); seen = 0
model.train()
for ep in range(a.epochs):
    run_loss, n_b = 0.0, 0
    for bi, (chunk, ids, att, yb) in enumerate(batches(tr_idx, a.batch, True)):
        if a.timing and bi == 2:                     # first batches include one-off start-up cost
            t_train = time.time(); seen = 0
        out = model(input_ids=ids, attention_mask=att, labels=yb)
        (out.loss / a.accum).backward()
        run_loss += out.loss.item(); n_b += 1; seen += len(chunk)
        if (bi + 1) % a.accum == 0:
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step(); sched.step(); opt.zero_grad()
        if (bi + 1) % 50 == 0:
            print(f"  epoch {ep+1} batch {bi+1} loss {run_loss/n_b:.3f}  {time.time()-t_train:.0f}s", flush=True)
    if n_b % a.accum:                            # flush leftover accumulated gradients
        opt.step(); sched.step(); opt.zero_grad()
    print(f"epoch {ep+1} done, mean loss {run_loss/max(1,n_b):.3f}, {time.time()-t_train:.0f}s", flush=True)
train_secs = time.time() - t_train

model.eval(); scores = np.zeros(len(df))
n_inf = 0; inf_secs = 0.0
with torch.no_grad():
    for bi, (chunk, ids, att, yb) in enumerate(batches(te_idx, 16, False)):
        t1 = time.time()
        p = torch.softmax(model(input_ids=ids, attention_mask=att).logits, -1)[:, 1]
        scores[chunk] = p.cpu().numpy()
        if not (a.timing and bi == 0):               # skip warm-up batch when timing
            inf_secs += time.time() - t1; n_inf += len(chunk)
n_inf = max(n_inf, 1)

yt, st_ = y_all[te_idx], scores[te_idx]
def passthrough(y, s, keep):
    thr = np.quantile(s[y == 1], 1 - keep)
    return float((s[y == 0] >= thr).mean())
if len(set(yt)) == 2:
    print("TEST  AUC %.3f  acc %.3f  FP pass-through at %.1f%% TP kept: %.3f" %
          (roc_auc_score(yt, st_), ((st_ >= .5) == yt).mean(), a.keep_tp * 100, passthrough(yt, st_, a.keep_tp)))
else:
    print("test fold has one class only; skipped metrics")

if a.timing:
    per_tr = train_secs / seen
    est = per_tr * full_tr * 3 + (inf_secs / n_inf) * full_te
    print("\nTIMING: %.2f s per training example, %.2f s per test example" % (per_tr, inf_secs / n_inf))
    print("ESTIMATE for this split with 3 epochs: about %.0f minutes (train %d, test %d)" % (est / 60, full_tr, full_te))
    print("(timing run only; nothing saved)")
else:
    out = df.loc[te_idx, ["case_id", "label", "category", "cwe"]].copy()
    out["score"] = scores[te_idx]
    out.to_csv(pred_path, index=False)
    with open(os.path.join(a.out, f"info_{run_name}.json"), "w") as f:
        json.dump({"args": vars(a), "input_stats": rep, "train_secs": train_secs}, f, indent=1, default=str)
    print("saved", pred_path)
