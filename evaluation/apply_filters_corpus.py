#!/usr/bin/env python3
"""
apply_filters_corpus.py — Apply noise filters F1–F4 to the full npm/PyPI corpus.

F5 (hunk-header-only) requires the raw diff and is omitted here; it would
require re-fetching diffs, which is a Phase 3 concern.

Reports:
  - Per-ecosystem: functions before/after, advisories affected
  - Overall totals suitable for paper reporting

Usage:
  python3 apply_filters_corpus.py
"""

import csv
import sys
from pathlib import Path
from collections import defaultdict

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
NPM_FILE = DATA_DIR / "ghsa_full_npm_extraction.csv"
PYPI_FILE = DATA_DIR / "ghsa_full_pypi_extraction.csv"


# ── Filter definitions (per-function, applied to each extracted name) ───

def f1_minified(fn: str) -> bool:
    """F1: ≤2 chars + starts with uppercase."""
    return len(fn) <= 2 and len(fn) >= 1 and fn[0].isupper()

def f2_generic(fn: str, num_funcs: int) -> bool:
    """F2: __init__/__post_init__ when num_funcs > 1; noop/datetime always."""
    if fn in ("__init__", "__post_init__") and num_funcs > 1:
        return True
    if fn in ("noop", "datetime"):
        return True
    return False

def f3_test(fn: str) -> bool:
    """F3: starts with test_."""
    return fn.startswith("test_")

def f4_count_cap(num_funcs: int) -> bool:
    """F4: advisory has ≥20 functions."""
    return num_funcs >= 20


def apply_filters_to_advisory(functions_str: str, num_funcs: int):
    """Apply F1–F4 to a semicolon-delimited function list.
    
    Returns (kept_funcs, removed_funcs, filter_reasons_per_removed).
    """
    if not functions_str or not functions_str.strip():
        return [], [], {}
    
    fns = [f.strip() for f in functions_str.split(";") if f.strip()]
    kept = []
    removed = []
    reasons = {}
    
    for fn in fns:
        fn_reasons = []
        if f1_minified(fn):
            fn_reasons.append("F1")
        if f2_generic(fn, num_funcs):
            fn_reasons.append("F2")
        if f3_test(fn):
            fn_reasons.append("F3")
        if f4_count_cap(num_funcs):
            fn_reasons.append("F4")
        
        if fn_reasons:
            removed.append(fn)
            reasons[fn] = fn_reasons
        else:
            kept.append(fn)
    
    return kept, removed, reasons


def process_ecosystem(filepath: Path, ecosystem: str):
    """Process one ecosystem CSV and return summary stats."""
    rows = list(csv.DictReader(open(filepath, encoding="utf-8-sig")))
    
    total_advisories = len(rows)
    advisories_with_funcs_before = 0
    advisories_with_funcs_after = 0
    total_funcs_before = 0
    total_funcs_after = 0
    total_removed = 0
    advisories_fully_filtered = 0
    
    filter_hit_counts = defaultdict(int)
    
    for row in rows:
        funcs_str = row.get("functions_mined", "")
        num_funcs = int(row.get("num_functions_mined", 0))
        
        if num_funcs == 0 or not funcs_str.strip():
            continue
        
        advisories_with_funcs_before += 1
        fns = [f.strip() for f in funcs_str.split(";") if f.strip()]
        total_funcs_before += len(fns)
        
        kept, removed, reasons = apply_filters_to_advisory(funcs_str, num_funcs)
        total_funcs_after += len(kept)
        total_removed += len(removed)
        
        for fn, fn_reasons in reasons.items():
            for r in fn_reasons:
                filter_hit_counts[r] += 1
        
        if kept:
            advisories_with_funcs_after += 1
        else:
            advisories_fully_filtered += 1
    
    return {
        "ecosystem": ecosystem,
        "total_advisories": total_advisories,
        "advisories_with_funcs_before": advisories_with_funcs_before,
        "advisories_with_funcs_after": advisories_with_funcs_after,
        "advisories_fully_filtered": advisories_fully_filtered,
        "total_funcs_before": total_funcs_before,
        "total_funcs_after": total_funcs_after,
        "total_removed": total_removed,
        "filter_hits": dict(filter_hit_counts),
    }


def main():
    print("=" * 70)
    print("CORPUS-LEVEL NOISE FILTER APPLICATION (F1–F4)")
    print("=" * 70)
    print("Note: F5 (hunk-header) requires raw diff access and is not applied.\n")
    
    results = []
    for filepath, eco in [(NPM_FILE, "npm"), (PYPI_FILE, "PyPI")]:
        if not filepath.exists():
            print(f"⚠️  {filepath} not found, skipping {eco}")
            continue
        r = process_ecosystem(filepath, eco)
        results.append(r)
        
        print(f"\n{'─' * 50}")
        print(f"  {eco.upper()}")
        print(f"{'─' * 50}")
        print(f"  Total advisories:          {r['total_advisories']:>6,}")
        print(f"  With extractions (before): {r['advisories_with_funcs_before']:>6,}")
        print(f"  With extractions (after):  {r['advisories_with_funcs_after']:>6,}")
        print(f"  Fully filtered out:        {r['advisories_fully_filtered']:>6,}")
        print(f"  Functions before:          {r['total_funcs_before']:>6,}")
        print(f"  Functions after:           {r['total_funcs_after']:>6,}")
        print(f"  Functions removed:         {r['total_removed']:>6,} "
              f"({r['total_removed']/r['total_funcs_before']*100:.1f}%)")
        print(f"  Per-filter hits:")
        for f in ["F1", "F2", "F3", "F4"]:
            print(f"    {f}: {r['filter_hits'].get(f, 0):>5,}")
    
    # Combined totals
    if len(results) == 2:
        total_before = sum(r["total_funcs_before"] for r in results)
        total_after = sum(r["total_funcs_after"] for r in results)
        total_removed = sum(r["total_removed"] for r in results)
        
        print(f"\n{'=' * 70}")
        print("COMBINED TOTALS (npm + PyPI)")
        print(f"{'=' * 70}")
        print(f"  Functions before: {total_before:>6,}")
        print(f"  Functions after:  {total_after:>6,}")
        print(f"  Removed:          {total_removed:>6,} ({total_removed/total_before*100:.1f}%)")


if __name__ == "__main__":
    main()
