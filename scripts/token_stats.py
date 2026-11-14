"""Count CodeBERT tokens for the dataset so we can decide how to fit 512 tokens.
Usage: python3 scripts/token_stats.py --csv ~/sifting-noise/work/dataset.csv
Needs: pip install transformers pandas   (downloads the tokenizer once, ~1 MB)
Reads only; changes nothing."""
import argparse
import pandas as pd
from transformers import AutoTokenizer

ap = argparse.ArgumentParser()
ap.add_argument("--csv", required=True)
ap.add_argument("--tokenizer", default="microsoft/codebert-base")
a = ap.parse_args()

df = pd.read_csv(a.csv, keep_default_na=False)
df = df[df["has_code"].astype(str).str.lower() == "true"].reset_index(drop=True)
tok = AutoTokenizer.from_pretrained(a.tokenizer)

def n_tokens(texts):
    enc = tok(list(texts), add_special_tokens=False, truncation=False)
    return pd.Series([len(x) for x in enc["input_ids"]])

df["t_alert"] = n_tokens(df["alert_text"])
df["t_window"] = n_tokens(df["code_window"])
df["t_full"] = n_tokens(df["code_masked"])
df["t_pair"] = df["t_alert"] + df["t_window"] + 3  # <s> a </s></s> b </s>

def show(name, s):
    q = s.quantile([.5, .75, .9, .99]).astype(int).tolist()
    print(f"{name:28s} median {q[0]:5d}  p75 {q[1]:5d}  p90 {q[2]:5d}  p99 {q[3]:5d}  "
          f"over 512: {(s > 512).mean()*100:5.1f}%")

print(f"{len(df)} cases with code")
show("alert_text", df["t_alert"])
show("code_window", df["t_window"])
show("whole file (masked)", df["t_full"])
show("alert + window", df["t_pair"])
print("\nBy label (alert + window, share over 512):")
print(df.groupby("label")["t_pair"].apply(lambda s: round((s > 512).mean()*100, 1)))
print("\nMedian tokens by label (window):")
print(df.groupby("label")["t_window"].median())
