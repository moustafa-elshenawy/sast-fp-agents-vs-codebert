"""Run CodeBERT once over every case and save its embeddings (no training).
Forward pass only, so it is far cheaper than fine-tuning, and every split can
then reuse the same embeddings (see embed_eval.py). Resumable: finished chunks
are kept, so you can stop (Ctrl+C) and start again with the same command.

Usage (from the repo folder):
  python3 scripts/embed_codebert.py --csv ~/sifting-noise/work/dataset.csv --inputs both
  python3 scripts/embed_codebert.py --csv ... --inputs code    # shortcut control
  python3 scripts/embed_codebert.py --csv ... --inputs alert   # shortcut control
  add --limit 64 for a quick speed test (writes nothing permanent)
"""
import argparse, glob, json, os, time
import numpy as np, pandas as pd, torch
from transformers import AutoTokenizer, AutoModel
from cb_inputs import encode_all, report

ap = argparse.ArgumentParser()
ap.add_argument("--csv", required=True)
ap.add_argument("--out", default=os.path.expanduser("~/sifting-noise/work/emb"))
ap.add_argument("--model", default="microsoft/codebert-base")
ap.add_argument("--inputs", choices=["both", "alert", "code"], default="both")
ap.add_argument("--batch", type=int, default=8)
ap.add_argument("--chunk", type=int, default=256)
ap.add_argument("--limit", type=int, default=0)
a = ap.parse_args()

dev = torch.device("cuda" if torch.cuda.is_available() else
                   "mps" if getattr(torch.backends, "mps", None) and torch.backends.mps.is_available() else "cpu")
df = pd.read_csv(a.csv, keep_default_na=False)
df = df[df["has_code"].astype(str).str.lower() == "true"].reset_index(drop=True)
if a.limit:
    df = df.sample(a.limit, random_state=0).reset_index(drop=True)
tok = AutoTokenizer.from_pretrained(a.model)
ids_all, st = encode_all(df, tok, a.inputs)
print("input stats:", json.dumps(report(st, df["label"].values)), flush=True)

model = AutoModel.from_pretrained(a.model).to(dev).eval()
cdir = os.path.join(a.out, "chunks_%s%s" % (a.inputs, "_test" if a.limit else ""))
os.makedirs(cdir, exist_ok=True)
N, t0, done_new = len(df), time.time(), 0
for start in range(0, N, a.chunk):
    path = os.path.join(cdir, "chunk_%05d.npz" % start)
    if os.path.exists(path):
        continue
    idx = sorted(range(start, min(N, start + a.chunk)), key=lambda i: len(ids_all[i]))
    mean_v, cls_v = {}, {}
    with torch.no_grad():
        for b in range(0, len(idx), a.batch):
            ch = idx[b:b + a.batch]
            L = max(len(ids_all[i]) for i in ch)
            ids = torch.full((len(ch), L), tok.pad_token_id, dtype=torch.long)
            att = torch.zeros((len(ch), L), dtype=torch.long)
            for k, i in enumerate(ch):
                n = len(ids_all[i]); ids[k, :n] = torch.tensor(ids_all[i]); att[k, :n] = 1
            h = model(input_ids=ids.to(dev), attention_mask=att.to(dev)).last_hidden_state
            m = att.to(dev).unsqueeze(-1).float()
            mean = ((h * m).sum(1) / m.sum(1)).cpu().numpy()
            cl = h[:, 0].cpu().numpy()
            for k, i in enumerate(ch):
                mean_v[i], cls_v[i] = mean[k], cl[k]
    order = sorted(mean_v)
    np.savez(path, case_id=np.asarray(df.loc[order, "case_id"].tolist(), dtype=str),
             mean=np.stack([mean_v[i] for i in order]), cls=np.stack([cls_v[i] for i in order]))
    done_new += len(order)
    el = time.time() - t0
    left = N - min(N, start + a.chunk)
    print("chunk %d-%d saved | %.2f s/case | about %.0f min left" %
          (start, start + len(order), el / done_new, el / done_new * left / 60), flush=True)

parts = [np.load(p) for p in sorted(glob.glob(os.path.join(cdir, "chunk_*.npz")))]
final = os.path.join(a.out, "emb_%s%s.npz" % (a.inputs, "_test" if a.limit else ""))
np.savez(final, case_id=np.concatenate([p["case_id"] for p in parts]),
         mean=np.concatenate([p["mean"] for p in parts]), cls=np.concatenate([p["cls"] for p in parts]))
print("saved", final, "(%d cases)" % sum(len(p["case_id"]) for p in parts))
