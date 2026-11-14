#!/usr/bin/env python3
"""Build the case-level dataset for the SAST false-positive filtering comparison.

One row per OWASP Benchmark case found in the released artifact:
  FP pool: non-vulnerable cases flagged by at least one SAST tool (expected 1,303)
  TP pool: vulnerable cases (expected 1,415; only 1,411 have saved agent runs)

Inputs (all inside --data-dir, the artifact's "shared" folder):
  owasp_fp/expectedresults-1.2.csv               ground-truth labels
  owasp_fp/triage-owasp-benchmark/*.json         SAST findings, FP pool
  owasp_tp/triage-owasp-benchmark-tp/*.json      SAST findings, TP pool
  owasp_{fp,tp}/runs/claude-sonnet-4-20250514/swe-agent/<case>/task.md
                                                 the Java file the agent was given

Output: one CSV row per case. Columns:
  case_id         bookkeeping and splitting ONLY. Never feed this to a model.
  pool            fp or tp (which folder the case came from)
  label           TP or FP, taken from expectedresults-1.2.csv
  cwe, category   from expectedresults-1.2.csv (for analysis and splits)
  tools           SAST tools that flagged the case, joined by ';'
  n_tools         number of tools
  n_findings      number of raw findings across tools
  alert_text      compact summary: one line per (tool, rule, message) group
  code_masked     the whole Java file, license header removed, test names masked
  code_window     the lines around the flagged lines (with context), masked
  n_code_lines, n_window_lines
  n_other_file_refs   CodeQL flow steps that point at a different file
  flagged_blank_lines, flagged_lines_total   alignment sanity check
  alert_truncated     True if some finding groups were dropped from alert_text
  has_code            False if task.md was missing or unreadable
"""
import argparse
import glob
import os
import re
import statistics
import sys
from collections import Counter, OrderedDict

import pandas as pd

RUN_DIR = os.path.join("runs", "claude-sonnet-4-20250514", "swe-agent")
TOOL_ORDER = ["CodeQL", "Semgrep", "Joern", "Sonarqube"]
NAME_RE = re.compile(r"BenchmarkTest\d{5}")
SERVLET_RE = re.compile(r"@WebServlet\([^)]*\)")
CATPATH_RE = re.compile(r"/[a-z]+-\d{2}/")
CASE_RE = re.compile(r"(BenchmarkTest\d{5})")


def mask(text):
    """Remove the test name and the servlet path (which names the category)."""
    text = SERVLET_RE.sub('@WebServlet(value = "/MASKED")', text)
    # category folders such as "/pathtraver-00/" reveal the CWE family
    text = CATPATH_RE.sub("/MASKED/", text)
    return NAME_RE.sub("BenchmarkTestXXXXX", text)


def strip_header(lines):
    """Drop a leading block comment (the license header)."""
    i = 0
    while i < len(lines) and not lines[i].strip():
        i += 1
    if i < len(lines) and lines[i].lstrip().startswith("/*"):
        j = i
        while j < len(lines) and "*/" not in lines[j]:
            j += 1
        return lines[j + 1:]
    return lines


def read_code_from_task_md(path):
    """Return the Java file as a list of lines, with original line numbering."""
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.read().split("\n")
    except OSError:
        return None
    start = next((i for i, l in enumerate(lines) if l.strip() == "### File"), None)
    if start is None:
        return None
    end = next((i for i, l in enumerate(lines)
                if i > start and l.startswith("### Finding")), None)
    if end is None:
        return None
    code = lines[start + 1:end]
    # Only remove a leading code fence. Do NOT drop leading blank lines:
    # that would shift every line number.
    if code and code[0].strip().startswith("```"):
        code = code[1:]
    while code and not code[-1].strip():
        code.pop()
    if code and code[-1].strip().startswith("```"):
        code = code[:-1]
    return code


def clean_codeql_message(text):
    return re.sub(r"\[([^\]]*)\]\(\d+\)", r"\1", text or "").strip()


def as_int(x):
    return x if isinstance(x, int) else None


def add_range(focus, lo, hi, cap=15):
    lo, hi = as_int(lo), as_int(hi)
    if lo is None:
        return
    if hi is None or hi < lo:
        hi = lo
    for n in range(lo, min(hi, lo + cap) + 1):
        focus.add(n)


def fmt_lines(ranges, cap=6):
    parts = []
    for lo, hi in ranges[:cap]:
        parts.append("L%d" % lo if hi in (None, lo) else "L%d-%d" % (lo, hi))
    if len(ranges) > cap:
        parts.append("...")
    return ", ".join(parts)


def collect_findings(raw, case_file_base):
    """Return (groups, focus_lines, n_findings, n_other_file_refs).

    groups: OrderedDict {(tool, rule, message): [(lo, hi), ...]}
    focus_lines: set of 1-based line numbers in the case's own file
    """
    groups = OrderedDict()
    focus = set()
    n_findings = 0
    other_refs = 0

    def add(tool, rule, msg, lo, hi):
        key = (tool, rule, msg)
        groups.setdefault(key, [])
        if as_int(lo) is not None:
            groups[key].append((lo, as_int(hi) or lo))

    for tool in TOOL_ORDER:
        items = raw.get(tool) or []
        for f in items:
            n_findings += 1
            if tool == "CodeQL" and isinstance(f, dict):
                rule = f.get("ruleId") or (f.get("rule") or {}).get("id") or "?"
                msg = clean_codeql_message((f.get("message") or {}).get("text"))
                primary = None
                for loc in f.get("locations") or []:
                    pl = loc.get("physicalLocation") or {}
                    uri = (pl.get("artifactLocation") or {}).get("uri", "")
                    reg = pl.get("region") or {}
                    if uri.endswith(case_file_base):
                        add_range(focus, reg.get("startLine"), reg.get("endLine"))
                        if primary is None:
                            primary = (reg.get("startLine"), reg.get("endLine"))
                    else:
                        other_refs += 1
                flow_lines = []
                for cf in f.get("codeFlows") or []:
                    for tf in cf.get("threadFlows") or []:
                        for tl in tf.get("locations") or []:
                            pl = ((tl.get("location") or {}).get("physicalLocation")) or {}
                            uri = (pl.get("artifactLocation") or {}).get("uri", "")
                            reg = pl.get("region") or {}
                            if uri.endswith(case_file_base):
                                add_range(focus, reg.get("startLine"), reg.get("startLine"))
                                if as_int(reg.get("startLine")) is not None:
                                    flow_lines.append(reg["startLine"])
                            else:
                                other_refs += 1
                lo, hi = primary if primary else (None, None)
                add(tool, rule, msg, lo, hi)
                if flow_lines:
                    # note the flow endpoints in the message, once per group
                    key = (tool, rule, msg)
                    groups[key].append(("flow", (flow_lines[0], flow_lines[-1])))
            elif tool == "Semgrep" and isinstance(f, dict):
                rule = str(f.get("check_id", "?")).split(".")[-1]
                msg = str((f.get("extra") or {}).get("message", "")).strip()
                msg = " ".join(msg.split())[:140]
                lo = (f.get("start") or {}).get("line")
                hi = (f.get("end") or {}).get("line")
                add_range(focus, lo, hi)
                add(tool, rule, msg, lo, hi)
            elif tool == "Sonarqube" and isinstance(f, dict):
                rule = f.get("rule", "?")
                msg = " ".join(str(f.get("message", "")).split())[:140]
                tr = f.get("textRange") or {}
                lo = f.get("line") or tr.get("startLine")
                hi = tr.get("endLine") or lo
                add_range(focus, lo, hi)
                add(tool, rule, msg, lo, hi)
            else:  # Joern: plain strings
                s = f if isinstance(f, str) else str(f)
                m = re.match(r"\s*Result:\s*([\d.]+)\s*:\s*(.*?):\s*[^\s:]*\.java:(\d+)", s)
                if m:
                    rule, msg, lo = "joern", m.group(2).strip(), int(m.group(3))
                else:
                    mm = re.search(r"\.java:(\d+)", s)
                    rule, msg = "joern", " ".join(s.split())[:120]
                    lo = int(mm.group(1)) if mm else None
                if lo is not None:
                    add_range(focus, lo, lo)
                add(tool, rule, msg, lo, lo)
    return groups, focus, n_findings, other_refs


def build_alert_text(groups, max_groups):
    lines = []
    shown = 0
    for (tool, rule, msg), ranges in groups.items():
        plain = [r for r in ranges if r[0] != "flow"]
        flows = [r for r in ranges if r[0] == "flow"]
        where = fmt_lines(plain)
        text = "%s | %s | %s" % (tool, rule, msg)
        if where:
            text += " | " + where
        if flows:
            if flows[0][1][0] != flows[0][1][1]:
                text += " | flow L%d>L%d" % flows[0][1]
        text = " ".join(text.split())  # messages can contain newlines
        lines.append(mask(text))
        shown += 1
        if shown >= max_groups:
            break
    truncated = len(groups) > max_groups
    if truncated:
        lines.append("(+%d more finding groups)" % (len(groups) - max_groups))
    return "\n".join(lines), truncated


def build_window(lines, focus, ctx=4, max_lines=70):
    n = len(lines)
    pts = sorted(p for p in focus if 1 <= p <= n)
    if not pts:
        return "", 0
    ivs = []
    for c in (ctx, 2, 1, 0):
        ivs = []
        for p in pts:
            lo, hi = max(1, p - c), min(n, p + c)
            if ivs and lo <= ivs[-1][1] + 1:
                ivs[-1][1] = max(ivs[-1][1], hi)
            else:
                ivs.append([lo, hi])
        if sum(h - l + 1 for l, h in ivs) <= max_lines:
            break
    out, used = [], 0
    for k, (lo, hi) in enumerate(ivs):
        if k:
            out.append("    // ...")
        for i in range(lo, hi + 1):
            if used >= max_lines:
                break
            out.append(lines[i - 1])
            used += 1
    return "\n".join(out), used


def load_labels(data_dir):
    path = os.path.join(data_dir, "owasp_fp", "expectedresults-1.2.csv")
    df = pd.read_csv(path, comment="#", header=None,
                     names=["test", "category", "real", "cwe"])
    df["real"] = df["real"].astype(str).str.strip().str.lower() == "true"
    return {r.test: (bool(r.real), r.category, int(r.cwe)) for r in df.itertuples()}


def case_files(data_dir, pool):
    sub = "owasp_fp" if pool == "fp" else "owasp_tp"
    folder = "triage-owasp-benchmark" if pool == "fp" else "triage-owasp-benchmark-tp"
    pattern = os.path.join(data_dir, sub, folder, "OWASP_benchmark_java_BenchmarkTest*.json")
    return sorted(glob.glob(pattern))


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data-dir", required=True,
                    help="the artifact's 'shared' folder, e.g. .../artifact-data/shared")
    ap.add_argument("--out", required=True, help="output CSV path")
    ap.add_argument("--limit", type=int, default=0,
                    help="if >0, take only the first N cases from EACH pool (dry run)")
    ap.add_argument("--show", type=int, default=0,
                    help="print this many example rows per pool")
    ap.add_argument("--max-groups", type=int, default=12)
    ap.add_argument("--max-window-lines", type=int, default=70)
    args = ap.parse_args()

    import json

    labels = load_labels(args.data_dir)
    rows, missing_code, mismatch = [], [], []
    shown = Counter()

    for pool in ("fp", "tp"):
        files = case_files(args.data_dir, pool)
        if args.limit:
            files = files[:args.limit]
        print("pool %s: %d task files" % (pool, len(files)))
        sub = "owasp_fp" if pool == "fp" else "owasp_tp"
        for path in files:
            case_id = CASE_RE.search(os.path.basename(path)).group(1)
            with open(path, encoding="utf-8") as f:
                task = json.load(f)
            real, category, cwe = labels.get(case_id, (None, "?", -1))
            if (pool == "tp") != bool(real):
                mismatch.append(case_id)
            base = os.path.basename(task.get("file", case_id + ".java"))
            groups, focus, n_find, other = collect_findings(task.get("raw_output") or {}, base)
            alert_text, truncated = build_alert_text(groups, args.max_groups)

            md = os.path.join(args.data_dir, sub, RUN_DIR, case_id, "task.md")
            code = read_code_from_task_md(md)
            has_code = code is not None
            if not has_code:
                missing_code.append(case_id)
                code = []
            masked = [mask(l) for l in code]
            window, n_win = build_window(masked, focus, 4, args.max_window_lines)
            body = strip_header(masked)
            flagged_total = len([p for p in focus if 1 <= p <= len(code)])
            flagged_blank = len([p for p in focus
                                 if 1 <= p <= len(code) and not code[p - 1].strip()])
            rows.append(OrderedDict([
                ("case_id", case_id), ("pool", pool),
                ("label", "TP" if real else "FP"),
                ("cwe", cwe), ("category", category),
                ("tools", ";".join(task.get("tool") or [])),
                ("n_tools", len(task.get("tool") or [])),
                ("n_findings", n_find), ("alert_text", alert_text),
                ("code_masked", "\n".join(body)), ("code_window", window),
                ("n_code_lines", len(code)), ("n_window_lines", n_win),
                ("n_other_file_refs", other),
                ("flagged_blank_lines", flagged_blank),
                ("flagged_lines_total", flagged_total),
                ("alert_truncated", truncated), ("has_code", has_code),
            ]))
            if shown[pool] < args.show:
                shown[pool] += 1
                print("\n" + "=" * 70)
                print("%s  pool=%s  label=%s  CWE-%s  tools=%s"
                      % (case_id, pool, rows[-1]["label"], cwe, rows[-1]["tools"]))
                print("--- alert_text ---\n" + alert_text)
                print("--- code_window (%d lines) ---" % n_win)
                print("\n".join(window.split("\n")[:40]))

    df = pd.DataFrame(rows)
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    df.to_csv(args.out, index=False)

    print("\n" + "=" * 70 + "\nSUMMARY")
    print("rows written:", len(df), "->", args.out)
    print(df.groupby(["pool", "label"]).size().to_string())
    print("label disagrees with pool folder:", len(mismatch), mismatch[:10])
    print("cases without readable task.md:", len(missing_code), missing_code[:10])
    ok = df[df.has_code]
    if len(ok):
        tot = int(ok.flagged_lines_total.sum())
        blank = int(ok.flagged_blank_lines.sum())
        print("alignment check: %d of %d flagged lines point at blank lines (%.1f%%)"
              % (blank, tot, 100.0 * blank / max(tot, 1)))
        print("cases with no flagged line inside the file:",
              int((ok.flagged_lines_total == 0).sum()))
        for col in ("n_code_lines", "n_window_lines", "n_findings", "n_tools", "n_other_file_refs"):
            print("median %-18s %s" % (col, statistics.median(ok[col])))
        for col in ("alert_text", "code_masked", "code_window"):
            print("median chars %-12s %s" % (col, statistics.median(ok[col].str.len())))
        print("alert_text truncated in %d cases" % int(ok.alert_truncated.sum()))


if __name__ == "__main__":
    sys.exit(main())
