"""Shared input builder for the CodeBERT scripts.

Each case becomes: [alert part] + [code part], each under its own token budget,
measured with the real tokenizer on the real joined text (the first version
summed per-line counts, which under-counted and left 50-69% of cases cut at 512).

Alert part: header with tools and finding count, then one line per (tool, rule)
  (messages shortened to 10 words, repeats merged as xN), whole lines dropped from
  the end if over budget.
Code part: indentation removed; flagged lines are taken first, then their
  neighbours, widening outwards, as many lines as fit the budget; gaps shown as '// ...'.
"""
import numpy as np
import pandas as pd

MAXLEN = 512
DEFAULT_BUDGET = {"both": (120, 370), "alert": (500, 0), "code": (0, 500)}


def _n(tok, text):
    return len(tok(text, add_special_tokens=False)["input_ids"]) if text else 0


def build_alert(row, tok, budget):
    head = "tools: %s; findings: %s" % (row["tools"].replace(";", ", "), row["n_findings"])
    raw = [l for l in row["alert_text"].split("\n") if l.strip()]
    merged = {}
    for l in raw:
        p = l.split(" | ")
        tool, rule = p[0], (p[1] if len(p) > 1 else "")
        msg = " ".join((p[2] if len(p) > 2 else "").split()[:10])
        where = p[3] if len(p) > 3 else ""
        m = merged.setdefault((tool, rule), {"msg": msg, "where": where, "n": 0})
        m["n"] += 1
    lines = []
    for (tool, rule), m in merged.items():
        s = "%s | %s | %s" % (tool, rule, m["msg"])
        if m["where"]:
            s += " | " + m["where"]
        if m["n"] > 1:
            s += " x%d" % m["n"]
        lines.append(s)
    kept = [head]
    for s in lines:
        if _n(tok, "\n".join(kept + [s])) <= budget:
            kept.append(s)
        else:
            break
    return "\n".join(kept), len(lines) - (len(kept) - 1)      # text, lines dropped


def _render(lines, sel):
    out, prev = [], None
    for i in sorted(sel):
        if prev is not None and i != prev + 1:
            out.append("// ...")
        out.append(lines[i].strip())
        prev = i
    return "\n".join(out)


def build_code(row, tok, budget):
    lines = row["code_masked"].split("\n")
    off = int(row["header_offset"])
    flags = sorted({int(p) - off - 1 for p in row["flag_lines"].split()
                    if p.strip() and 1 <= int(p) - off <= len(lines)})
    flags = [f for f in flags if lines[f].strip()]
    order, seen = [], set()
    def add(i):
        if 0 <= i < len(lines) and i not in seen and lines[i].strip():
            seen.add(i); order.append(i)
    if flags:
        for f in flags:
            add(f)
        for d in range(1, len(lines)):
            for f in flags:
                add(f - d); add(f + d)
    else:                                   # no flagged line inside the file: file start
        for i in range(len(lines)):
            add(i)
    lo, hi = 0, len(order)                  # largest k whose rendered text fits
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if _n(tok, _render(lines, order[:mid])) <= budget:
            lo = mid
        else:
            hi = mid - 1
    sel = order[:lo]
    kept_flags = len(set(sel) & set(flags))
    return _render(lines, sel), len(flags), kept_flags


def encode_all(df, tok, inputs="both", alert_budget=None, code_budget=None):
    a_b, c_b = DEFAULT_BUDGET[inputs]
    a_b = a_b if alert_budget is None else alert_budget
    c_b = c_b if code_budget is None else code_budget
    ids_all, stats = [], []
    for _, r in df.iterrows():
        st, at, ct = {}, None, None
        if a_b > 0:
            at, st["alert_lines_dropped"] = build_alert(r, tok, a_b)
        if c_b > 0:
            ct, st["flags"], st["flags_kept"] = build_code(r, tok, c_b)
        if at is not None and ct is not None:
            args = (at, ct)
        else:
            args = (at if at is not None else ct,)
        full = tok(*args, truncation=False)["input_ids"]
        enc = tok(*args, truncation="only_second" if len(args) == 2 else True, max_length=MAXLEN)
        st["final_cut"] = int(len(full) > MAXLEN)
        st["n_tokens"] = len(enc["input_ids"])
        ids_all.append(enc["input_ids"]); stats.append(st)
    return ids_all, pd.DataFrame(stats)


def report(stats, labels):
    s = stats.copy(); s["label"] = np.asarray(labels)
    rep = {"mean_tokens": round(float(s["n_tokens"].mean()), 1),
           "share_cut_at_512": s.groupby("label")["final_cut"].mean().round(4).to_dict()}
    if "flags" in s:
        rep["share_cases_losing_flagged_lines"] = ((s["flags"] - s["flags_kept"]) > 0).groupby(s["label"]).mean().round(4).to_dict()
    if "alert_lines_dropped" in s:
        rep["share_cases_with_alert_lines_dropped"] = (s["alert_lines_dropped"] > 0).groupby(s["label"]).mean().round(4).to_dict()
    return rep
