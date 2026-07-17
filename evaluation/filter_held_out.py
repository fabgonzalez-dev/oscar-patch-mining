#!/usr/bin/env python3
"""
filter_held_out.py — Evaluate F1–F4 noise filters on the held-out Java
precision validation set (n=20).

This set was labeled independently and was NOT used to design the filters,
making it a valid held-out generalization test.

F5 (hunk-header-only) is skipped because it requires diff re-parsing
and diffs are not cached for the Java set.

Outputs:
  - Per-filter hit counts by verdict category
  - Pre/post precision (strict and relaxed)
  - evaluation/filter_held_out_results.json for consistency guard
"""

import csv
import json
from pathlib import Path

EVAL_DIR = Path(__file__).resolve().parent
JAVA_CSV = EVAL_DIR / "java_precision_validation.csv"
OUTPUT_JSON = EVAL_DIR / "filter_held_out_results.json"


# ── Filter definitions (same logic as noise_filter.py) ───────────────

def f1_minified_identifier(row: dict) -> bool:
    """F1: Function name ≤2 chars and starts with uppercase (minified)."""
    fn = row["function_name"].strip()
    return len(fn) <= 2 and len(fn) >= 1 and fn[0].isupper()


def f2_generic_identifier(row: dict) -> bool:
    """F2: Generic identifier blocklist.
    - __init__ / __post_init__: blocked only when num_functions > 1
    - noop / datetime: blocked unconditionally
    """
    fn = row["function_name"].strip()
    num_funcs = int(row["num_functions"])

    if fn in ("__init__", "__post_init__") and num_funcs > 1:
        return True
    if fn in ("noop", "datetime"):
        return True
    return False


def f3_test_function(row: dict) -> bool:
    """F3: Function name starts with test_ (test function)."""
    fn = row["function_name"].strip()
    return fn.startswith("test_")


def f4_function_count_cap(row: dict) -> bool:
    """F4: Advisory has ≥20 extracted functions (dilution noise)."""
    return int(row["num_functions"]) >= 20


FILTERS = [
    ("F1_minified", f1_minified_identifier),
    ("F2_generic", f2_generic_identifier),
    ("F3_test", f3_test_function),
    ("F4_dilution", f4_function_count_cap),
]


def main():
    # Load data
    with open(JAVA_CSV, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    n_total = len(rows)
    print(f"Loaded {n_total} samples from {JAVA_CSV.name}")
    print()

    # Count verdicts
    verdict_counts = {}
    for r in rows:
        v = r["verdict"].strip()
        verdict_counts[v] = verdict_counts.get(v, 0) + 1
    print("Verdict distribution:")
    for v, c in sorted(verdict_counts.items()):
        print(f"  {v}: {c}")
    print()

    # Pre-filter precision
    central = sum(1 for r in rows if r["verdict"].strip() == "Central")
    tangential = sum(1 for r in rows if r["verdict"].strip() == "Tangential")
    noise = sum(1 for r in rows if r["verdict"].strip() == "Noise")
    strict_pre = central / n_total * 100
    relaxed_pre = (central + tangential) / n_total * 100
    print(f"Pre-filter precision:")
    print(f"  Strict:  {central}/{n_total} = {strict_pre:.1f}%")
    print(f"  Relaxed: {central + tangential}/{n_total} = {relaxed_pre:.1f}%")
    print()

    # Per-filter analysis
    print("Per-filter hits:")
    print(f"  {'Filter':<15} {'Total':>5} {'Central':>8} {'Tang.':>6} {'Noise':>6}")
    print("  " + "-" * 42)

    filter_hits = {}
    for fname, ffunc in FILTERS:
        hits = [r for r in rows if ffunc(r)]
        hit_central = sum(1 for r in hits if r["verdict"].strip() == "Central")
        hit_tang = sum(1 for r in hits if r["verdict"].strip() == "Tangential")
        hit_noise = sum(1 for r in hits if r["verdict"].strip() == "Noise")
        filter_hits[fname] = {
            "total": len(hits),
            "central": hit_central,
            "tangential": hit_tang,
            "noise": hit_noise,
            "samples": [r["function_name"].strip() for r in hits],
        }
        print(f"  {fname:<15} {len(hits):>5} {hit_central:>8} {hit_tang:>6} {hit_noise:>6}")

    print()

    # Combined filter
    filtered_out = set()
    filter_reasons = {}
    for fname, ffunc in FILTERS:
        for i, r in enumerate(rows):
            if ffunc(r) and i not in filtered_out:
                filtered_out.add(i)
                filter_reasons[i] = fname

    surviving = [r for i, r in enumerate(rows) if i not in filtered_out]
    removed = [r for i, r in enumerate(rows) if i in filtered_out]

    n_post = len(surviving)
    central_post = sum(1 for r in surviving if r["verdict"].strip() == "Central")
    tangential_post = sum(1 for r in surviving if r["verdict"].strip() == "Tangential")
    noise_post = sum(1 for r in surviving if r["verdict"].strip() == "Noise")
    strict_post = central_post / n_post * 100 if n_post > 0 else 0
    relaxed_post = (central_post + tangential_post) / n_post * 100 if n_post > 0 else 0

    # Count false positives (Central or Tangential removed)
    fp_central = sum(1 for r in removed if r["verdict"].strip() == "Central")
    fp_tangential = sum(1 for r in removed if r["verdict"].strip() == "Tangential")

    print(f"Combined filter results:")
    print(f"  Removed: {len(removed)} samples")
    for i in sorted(filtered_out):
        r = rows[i]
        print(f"    [{filter_reasons[i]}] {r['function_name'].strip()} "
              f"(verdict={r['verdict'].strip()}, n_funcs={r['num_functions']})")
    print(f"  Central false positives: {fp_central}")
    print(f"  Tangential false positives: {fp_tangential}")
    print()

    print(f"Post-filter precision (n={n_post}):")
    print(f"  Strict:  {central_post}/{n_post} = {strict_post:.1f}%")
    print(f"  Relaxed: {central_post + tangential_post}/{n_post} = {relaxed_post:.1f}%")
    print()

    print(f"Delta Strict:  {strict_post - strict_pre:+.1f} pts")
    print(f"Delta Relaxed: {relaxed_post - relaxed_pre:+.1f} pts")

    # Save results
    results = {
        "dataset": "java_precision_validation.csv",
        "n_total": n_total,
        "pre_filter": {
            "strict_pct": round(strict_pre, 1),
            "relaxed_pct": round(relaxed_pre, 1),
            "central": central,
            "tangential": tangential,
            "noise": noise,
        },
        "post_filter": {
            "n": n_post,
            "strict_pct": round(strict_post, 1),
            "relaxed_pct": round(relaxed_post, 1),
            "central": central_post,
            "tangential": tangential_post,
            "noise": noise_post,
        },
        "removed": {
            "total": len(removed),
            "central_fp": fp_central,
            "tangential_fp": fp_tangential,
            "noise_tp": sum(1 for r in removed if r["verdict"].strip() == "Noise"),
        },
        "per_filter": filter_hits,
    }

    with open(OUTPUT_JSON, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nResults saved to {OUTPUT_JSON.name}")


if __name__ == "__main__":
    main()
