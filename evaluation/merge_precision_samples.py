#!/usr/bin/env python3
"""
Merge the two JS/Python precision-validation files into one canonical n=105 file.

Inputs (unchanged by this script):
  - precision_validation_samples.csv        (initial 50-sample validation)
  - precision_validation_samples_extra.csv  (55-sample extension)

Output:
  - precision_validation_samples_n104.csv   (canonical merged, deduped set)

The merge:
  * adds `sample_set`     -> initial_50 | extension_55  (provenance)
  * adds `orig_sample_id` -> the per-file id (kept for traceability)
  * reassigns `sample_id` -> global 1..N
  * normalises `severity` -> {Critical, High, Moderate, Low}
                             (source files disagree on case, and use
                              MODERATE vs medium for the same level)
  * DEDUPES on (vuln_id, function_name): the initial 50-set contains one
    genuine double-count -- GHSA-v6h2-p8h4-qcjw / `expand` (brace-expansion
    ReDoS, CVE-2025-5889) appears as rows #23 and #34 with conflicting
    severity (Low vs High). OSV confirms the advisory is LOW, so the first
    occurrence (#23, Low) is kept and the later High-severity row is dropped.
    Result: n=104 distinct (advisory, function) samples.

Run from the evaluation/ directory:  python3 merge_precision_samples.py
"""
import csv
from collections import Counter, defaultdict

SRC = [
    ("precision_validation_samples.csv", "initial_50"),
    ("precision_validation_samples_extra.csv", "extension_55"),
]
OUT = "precision_validation_samples_n104.csv"

SEV_MAP = {
    "critical": "Critical", "high": "High",
    "moderate": "Moderate", "medium": "Moderate", "low": "Low",
}


def norm_sev(s):
    s = (s or "").strip()
    return SEV_MAP.get(s.lower(), s.title())


def main():
    rows = []
    for path, batch in SRC:
        with open(path, newline="") as f:
            for r in csv.DictReader(f):
                r = dict(r)
                r["sample_set"] = batch
                r["orig_sample_id"] = r["sample_id"]
                r["severity"] = norm_sev(r["severity"])
                rows.append(r)

    # dedupe on (vuln_id, function_name): keep first occurrence (correct Low row)
    seen = set()
    deduped, dropped = [], []
    for r in rows:
        k = (r["vuln_id"], r["function_name"])
        (dropped if k in seen else deduped).append(r)
        seen.add(k)
    rows = deduped

    # global re-id
    for i, r in enumerate(rows, 1):
        r["sample_id"] = i

    # column order: ids + provenance first, then original schema
    base_cols = [
        "vuln_id", "package", "ecosystem", "severity", "function_name",
        "num_functions_in_advisory", "confidence", "source_repo",
        "ghsa_url", "verdict", "reasoning",
    ]
    cols = ["sample_id", "sample_set", "orig_sample_id"] + base_cols

    with open(OUT, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)

    # ---------------- verification ----------------
    n = len(rows)
    adv = {r["vuln_id"] for r in rows}
    vc = Counter(r["verdict"].strip() for r in rows)
    cen, tan, noi = vc["Central"], vc["Tangential"], vc["Noise"]
    print(f"WROTE {OUT}: {n} rows, {len(adv)} distinct advisories")
    print(f"  verdicts: Central={cen} Tangential={tan} Noise={noi}")
    print(f"  strict  = {cen}/{n} = {cen/n*100:.1f}%")
    print(f"  relaxed = {cen+tan}/{n} = {(cen+tan)/n*100:.1f}%")

    tier = defaultdict(Counter)
    for r in rows:
        tier[r["confidence"].strip()][r["verdict"].strip()] += 1
    for t in ["High", "Medium", "Low"]:
        d = tier[t]; tn = sum(d.values())
        if tn:
            print(f"  {t:6s} n={tn:3d}  C={d['Central']} T={d['Tangential']} N={d['Noise']}"
                  f"  strict={d['Central']/tn*100:.1f}%  relaxed={(d['Central']+d['Tangential'])/tn*100:.1f}%")

    # severity by row and by distinct advisory
    print("  severity (by row):     ", dict(Counter(r["severity"] for r in rows)))
    sev_adv = {}
    for r in rows:
        sev_adv[r["vuln_id"]] = r["severity"]
    print("  severity (by advisory):", dict(Counter(sev_adv.values())))

    # dropped-row report
    if dropped:
        print(f"\n  DEDUPED: dropped {len(dropped)} duplicate row(s):")
        for r in dropped:
            print(f"    {r['sample_set']}:{r['orig_sample_id']}  {r['vuln_id']} / {r['function_name']}"
                  f"  (sev={r['severity']}, {r['confidence']}, {r['verdict']})")
    else:
        print("\n  No duplicates dropped.")

    # noise dump for failure-mode re-tally
    noise = [r for r in rows if r["verdict"].strip() == "Noise"]
    print(f"\n  === {len(noise)} NOISE samples (for failure-mode taxonomy) ===")
    for r in noise:
        print(f"  [{r['sample_set'][:4]}] {r['package']}/{r['function_name']} "
              f"(nf={r['num_functions_in_advisory']},{r['confidence']}): {r['reasoning'][:160]}")


if __name__ == "__main__":
    main()
