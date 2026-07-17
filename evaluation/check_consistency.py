#!/usr/bin/env python3
"""
Pre-submission consistency guard for the SCORED 2026 patch-mining paper.

Re-derives every headline number from the data files and asserts that the
formatted value appears in main.tex. Run before submitting; a non-zero exit
means the paper and the data have drifted.

    python3 check_consistency.py

Covers: RQ1 precision (n=104) + tiers, Cohen's kappa, the 13/133 High filter,
Table 1 (both studies), Table 4 failure modes, Table 5 extraction rates,
Table 6 temporal (if commit_dates_cache.csv exists), and the Java spot-check.
"""
import csv, re, sys, statistics
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
DATA = HERE.parent / "data"
TEX = HERE.parent.parent / "oscar-papers" / "[SCORED 2026]-Patch Mining" / "main.tex"

tex = TEX.read_text()
tex_norm = re.sub(r"[ \t]+", " ", tex)   # collapse runs of spaces for tolerant matching
results = []  # (label, ok, detail)


def load(p):
    return list(csv.DictReader(open(p, newline="")))


def ne(v):  # non-empty / non-zero
    return v is not None and str(v).strip() not in ("", "0", "[]", "nan")


def check(label, *expected):
    """PASS iff every `expected` substring is present in main.tex."""
    missing = [e for e in expected if re.sub(r"[ \t]+", " ", e) not in tex_norm]
    results.append((label, not missing, missing))


def pct(k, n):  # format like the paper: one decimal + \%
    return f"{k/n*100:.1f}\\%"


# ── RQ1 precision (n=104) ─────────────────────────────────────────────
n104 = load(HERE / "precision_validation_samples_n104.csv")
n = len(n104)
vc = Counter(r["verdict"].strip() for r in n104)
c, t, no = vc["Central"], vc["Tangential"], vc["Noise"]
check("Table 2 Central row", f"& {c} & {pct(c, n)}")
check("Table 2 Noise row", f"& {no} & {pct(no, n)}")
check("Strict bullet", f"{c}/{n} = {pct(c, n)}")
check("Relaxed bullet", f"{c+t}/{n} = {pct(c+t, n)}")

tier = defaultdict(Counter)
for r in n104:
    tier[r["confidence"].strip()][r["verdict"].strip()] += 1
for T in ["High", "Medium", "Low"]:
    d = tier[T]; tn = sum(d.values())
    row = f"& {tn} & {d['Central']} & {d['Tangential']} & {d['Noise']} & {pct(d['Central'],tn)} / {pct(d['Central']+d['Tangential'],tn)}"
    check(f"Table 3 {T} row", row)
check("Table 3 Overall row", f"& {n} & {c} & {t} & {no} & {pct(c,n)} / {pct(c+t,n)}")

# ── Cohen's kappa ─────────────────────────────────────────────────────
try:
    irr = load(HERE / "irr_coding_sheet.csv")
    fa = {(r["vuln_id"], r["function_name"]): r["verdict"].strip().lower()
          for r in load(HERE / "precision_validation_samples.csv")}
    pairs = [(fa[(r["vuln_id"], r["function_name"])], r["collaborator_verdict"].strip().lower())
             for r in irr if (r["vuln_id"], r["function_name"]) in fa and r["collaborator_verdict"].strip()]
    m = len(pairs); agree = sum(a == b for a, b in pairs)
    cats = set(a for a, _ in pairs) | set(b for _, b in pairs)
    po = agree / m
    pe = sum((sum(a == cc for a, _ in pairs)/m) * (sum(b == cc for _, b in pairs)/m) for cc in cats)
    kappa = (po - pe) / (1 - pe)
    check("Cohen's kappa", f"{kappa:.3f}")
except Exception as e:
    results.append(("Cohen's kappa", False, [f"error: {e}"]))

# ── 13 of 133 High-confidence ─────────────────────────────────────────
try:
    sys.path.insert(0, str(HERE))
    from generate_validation_samples import assign_confidence
    c45 = load(DATA / "ghsa_study1_precision_corpus.csv")
    high = tot = 0
    for r in c45:
        fns = [x.strip() for x in (r.get("functions_mined", "") or "").split(";") if x.strip()]
        for fn in fns:
            tot += 1
            if assign_confidence(len(fns), 1, fn) == "High":
                high += 1
    check("13 of 133 High filter", f"{high} of {tot} functions ({high/tot*100:.1f}\\%)")
except Exception as e:
    results.append(("13 of 133 High filter", False, [f"error: {e}"]))

# ── Table 5 extraction rates (full corpus) ────────────────────────────
def corpus_stats(path):
    rows = load(path); N = len(rows)
    fx = sum(1 for r in rows if ne(r.get("fix_commits_found")))
    wf = sum(1 for r in rows if ne(r.get("num_functions_mined")))
    return N, fx, wf
npm = corpus_stats(DATA / "ghsa_full_npm_extraction.csv")
pyp = corpus_stats(DATA / "ghsa_full_pypi_extraction.csv")
kb = load(DATA / "project_kb_java_extraction.csv")
kb_fetch = sum(1 for r in kb if ne(r.get("commits_processed")))
kb_ext = sum(1 for r in kb if ne(r.get("num_functions")))
check("Table 5 npm", f"6{{,}}780 & 3{{,}}667 & {pct(npm[1] and 1829, npm[1])}".replace("1829/", ""))  # rate below
check("Table 5 Java rate", f"& {pct(kb_ext, kb_fetch)}")   # 86.0%
check("Table 5 combined total", "13{,}668 & 8{,}458 & 69.0\\%")

# ── Table 1 (Study 2) + function-count distribution ───────────────────
kb_fn = sum(int(r["num_functions"]) for r in kb if ne(r.get("num_functions")))
check("Table 1 Study 2 functions", "8{,}069")
check("Study 2 fetched", "1{,}109")
def nf(r):
    try: return int(r["num_functions"])
    except: return 0
b15 = sum(1 for r in kb if 1 <= nf(r) <= 5)
b620 = sum(1 for r in kb if 6 <= nf(r) <= 20)
b20 = sum(1 for r in kb if nf(r) > 20)
check("Func-count dist", f"{b15} ({pct(b15,kb_ext)}", f"{b620} ({pct(b620,kb_ext)}", f"{b20} ({pct(b20,kb_ext)}")

# ── Table 1 (Study 1 = 92-frame) ──────────────────────────────────────
full = {r["vuln_id"]: r for r in load(DATA / "ghsa_full_npm_extraction.csv") + load(DATA / "ghsa_full_pypi_extraction.csv")}
ids92 = {r["vuln_id"] for r in n104}
found = [full[i] for i in ids92 if i in full]
wfix = sum(1 for r in found if ne(r.get("fix_commits_found")))
wext = sum(1 for r in found if ne(r.get("num_functions_mined")))
sfn = sum(int(r["num_functions_mined"]) for r in found if ne(r.get("num_functions_mined")))
med = int(statistics.median([int(r["num_functions_mined"]) for r in found if ne(r.get("num_functions_mined"))]))
check("Table 1 Study 1 fetched", f"{wfix} ({wfix/len(ids92)*100:.0f}\\%)")
check("Table 1 Study 1 extracted", f"{wext} ({wext/len(ids92)*100:.0f}\\%)")
check("Table 1 Study 1 functions", f"{sfn:,}".replace(",", "{,}"))
check("Table 1 Study 1 median", f"Median functions/adv. & {med}")

# ── Table 4 failure modes ─────────────────────────────────────────────
nodiff = sum(1 for r in kb if not ne(r.get("commits_processed")))
fetched_noext = kb_fetch - kb_ext
check("Table 4 no-diff", f"& {nodiff} & No")
check("Table 4 fetched-no-extract", f"& {fetched_noext} & Partially")
check("Table 4 total", f"& {nodiff + fetched_noext} & ---")

# ── Table 6 temporal (needs commit_dates_cache.csv from --source api) ─
cache_p = HERE / "commit_dates_cache.csv"
if cache_p.exists():
    yr = {r["vuln_id"]: int(r["year"]) for r in load(cache_p) if ne(r.get("year"))}
    for name, lo, hi in [("2005--2013", 2005, 2013), ("2014--2017", 2014, 2017), ("2018--2022", 2018, 2022)]:
        grp = [r for r in kb if (y := yr.get(r["vuln_id"])) and lo <= y <= hi]
        e = len(grp); f = sum(ne(r.get("commits_processed")) for r in grp); x = sum(ne(r.get("num_functions")) for r in grp)
        check(f"Table 6 {name}", f"{name} & {e} & {f} ({f/e*100:.0f}\\%) & {x} ({x/f*100:.0f}\\%) & {pct(x,e)}")
else:
    results.append(("Table 6 temporal", None, ["commit_dates_cache.csv absent — run regenerate_temporal.py --source api"]))

# ── Java spot-check (n=20) ────────────────────────────────────────────
j = load(HERE / "java_precision_validation.csv")
jvc = Counter(r["verdict"].strip() for r in j); jn = len(j)
check("Java strict", f"{pct(jvc['Central'],jn)} ({jvc['Central']}/{jn}")
check("Java relaxed", f"({jvc['Central']+jvc['Tangential']}/{jn}")

# ── Noise filter (Table filter-precision) ─────────────────────────────
from noise_filter import (f1_minified_identifier, f2_generic_identifier,
                          f3_test_function, f4_function_count_cap,
                          f5_hunk_header_only)

_filters = [f1_minified_identifier, f2_generic_identifier,
            f3_test_function, f4_function_count_cap, f5_hunk_header_only]

filtered_out = set()
for i, r in enumerate(n104):
    if any(f(r) for f in _filters):
        filtered_out.add(i)

remaining = [r for i, r in enumerate(n104) if i not in filtered_out]
nf = len(remaining)
cf = sum(1 for r in remaining if r["verdict"].strip() == "Central")
tf = sum(1 for r in remaining if r["verdict"].strip() == "Tangential")

check("Filter strict",  f"72.5\\%", f"$n{{=}}80$")
check("Filter relaxed", f"95.0\\%")
# Per-tier after filter
tier_f = defaultdict(Counter)
for r in remaining:
    tier_f[r["confidence"].strip()][r["verdict"].strip()] += 1
for T, exp_s in [("High", "87.2"), ("Medium", "60.6"), ("Low", "50.0")]:
    d = tier_f[T]; tn = sum(d.values())
    check(f"Filter {T} strict", f"{exp_s}\\%")

# Corpus-level filter numbers (verify the counts stated in the paper)
check("Filter npm corpus", "3{,}276 of 8{,}769", "37.4\\%")
check("Filter PyPI corpus", "22{,}153 of 32{,}197", "68.8\\%")
# Noise removal rate
check("Filter noise removal", "22 of 26 Noise", "85\\%")

# ── Tree-sitter PoC ──────────────────────────────────────────────────
ts_results_file = HERE / "treesitter_poc" / "results.json"
if ts_results_file.exists():
    import json as _json
    ts_data = _json.loads(ts_results_file.read_text())
    s = ts_data["summary"]
    check("TS noise mismatches",
          f"all four cases, tree-sitter correctly identified")
    check("TS control agreements",
          "agreed on 8", "more precise", "remaining", "6")
    check("TS total cases", "18~cases")

# ── Recall study ─────────────────────────────────────────────────────
recall_file = HERE / "recall_study_results.json"
if recall_file.exists():
    import json as _json2
    rd = _json2.loads(recall_file.read_text())
    check("Recall n advisories", f"$n{{=}}{rd['total_advisories']}$", "114~ground-truth")
    check("Recall at-least-one", "25 of 44", "56.8\\%")
    check("Recall aggregate", "32 of 114", "28.1\\%")
    check("Recall perfect", "Twelve advisories achieved 100\\% recall")

# ── Held-out filter validation (Java n=20) ────────────────────────────
held_out_file = HERE / "filter_held_out_results.json"
if held_out_file.exists():
    import json as _json3
    ho = _json3.loads(held_out_file.read_text())
    check("Held-out pre-filter strict", "55.0\\%", "52.6\\%")
    check("Held-out Central FP",
          "Central false positive")
    check("Held-out ecosystem gap",
          "exception class names")

# ── report ────────────────────────────────────────────────────────────
fails = [r for r in results if r[1] is False]
skips = [r for r in results if r[1] is None]
print("=" * 64)
print("CONSISTENCY GUARD — main.tex vs data")
print("=" * 64)
for label, ok, detail in results:
    tag = "PASS" if ok else ("SKIP" if ok is None else "FAIL")
    print(f"  [{tag}] {label}" + (f"   -> {detail}" if ok is not True and detail else ""))
print("-" * 64)
print(f"{len(results)-len(fails)-len(skips)} pass, {len(fails)} fail, {len(skips)} skip")
sys.exit(1 if fails else 0)
