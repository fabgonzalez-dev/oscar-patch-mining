#!/usr/bin/env python3
"""
compute_recall_extended.py — Compute recall combining original (n=19) and
extended (n=26) recall study samples.

Outputs:
  - Per-advisory recall (at-least-one and exact)
  - Aggregate function-level recall
  - Updated recall_study_results.json for consistency guard
"""

import csv
import json
from pathlib import Path
from collections import Counter

EVAL_DIR = Path(__file__).resolve().parent
ORIGINAL_CSV = EVAL_DIR / "recall_study_samples.csv"
EXTENDED_CSV = EVAL_DIR / "recall_study_samples_extended.csv"
OUTPUT_JSON = EVAL_DIR / "recall_study_results.json"


def parse_func_list(s):
    """Parse semicolon-separated function list, stripping whitespace."""
    if not s or not s.strip():
        return []
    return [f.strip() for f in s.split(";") if f.strip()]


def compute_recall(rows, label=""):
    """Compute recall metrics for a set of rows."""
    total_advisories = 0
    at_least_one = 0
    perfect = 0
    total_gt = 0
    total_matched = 0
    skipped = 0

    results = []

    for r in rows:
        vuln_id = r["vuln_id"].strip()
        extracted = set(parse_func_list(r.get("extracted_functions", "")))
        ground_truth = set(parse_func_list(r.get("ground_truth_functions", "")))

        # Skip if no ground truth or explicit skip marker
        notes = r.get("notes", "").strip()
        if not ground_truth:
            skipped += 1
            continue
        if "UNVERIFIED" in notes or "N/A" in notes or "Recommend excluding" in notes:
            skipped += 1
            continue

        total_advisories += 1
        gt_count = len(ground_truth)
        total_gt += gt_count

        # Case-insensitive matching
        extracted_lower = {f.lower() for f in extracted}
        gt_lower = {f.lower() for f in ground_truth}
        matched = extracted_lower & gt_lower
        matched_count = len(matched)
        total_matched += matched_count

        adv_recall = matched_count / gt_count if gt_count > 0 else 0
        has_match = matched_count > 0
        is_perfect = matched_count == gt_count

        if has_match:
            at_least_one += 1
        if is_perfect:
            perfect += 1

        results.append({
            "vuln_id": vuln_id,
            "ecosystem": r.get("ecosystem", ""),
            "extracted": sorted(extracted),
            "ground_truth": sorted(ground_truth),
            "matched": sorted(matched),
            "recall": round(adv_recall, 3),
            "at_least_one": has_match,
            "perfect": is_perfect,
        })

    agg_recall = total_matched / total_gt * 100 if total_gt > 0 else 0
    at_least_one_pct = at_least_one / total_advisories * 100 if total_advisories > 0 else 0

    print(f"\n{'='*60}")
    print(f"  {label}")
    print(f"{'='*60}")
    print(f"  Advisories:      {total_advisories} (skipped: {skipped})")
    print(f"  Ground-truth fn: {total_gt}")
    print(f"  Matched fn:      {total_matched}")
    print(f"  Aggregate recall:{agg_recall:>7.1f}% ({total_matched}/{total_gt})")
    print(f"  At-least-one:    {at_least_one_pct:>7.1f}% ({at_least_one}/{total_advisories})")
    print(f"  Perfect recall:  {perfect}/{total_advisories}")
    print()

    # Per-advisory detail
    for res in sorted(results, key=lambda x: x["recall"], reverse=True):
        tag = "✓" if res["at_least_one"] else "✗"
        perf = " [PERFECT]" if res["perfect"] else ""
        print(f"  {tag} {res['vuln_id']:<30} recall={res['recall']:.1%}  "
              f"matched={len(res['matched'])}/{len(res['ground_truth'])}{perf}")
        if not res["at_least_one"]:
            print(f"      extracted: {res['extracted']}")
            print(f"      gt:        {res['ground_truth']}")

    return {
        "total_advisories": total_advisories,
        "skipped": skipped,
        "total_gt_functions": total_gt,
        "total_matched": total_matched,
        "aggregate_recall_pct": round(agg_recall, 1),
        "at_least_one": at_least_one,
        "at_least_one_pct": round(at_least_one_pct, 1),
        "perfect": perfect,
        "per_advisory": results,
    }


def main():
    # Load original
    with open(ORIGINAL_CSV, newline="", encoding="utf-8-sig") as f:
        original_rows = list(csv.DictReader(f))

    # Load extended
    with open(EXTENDED_CSV, newline="", encoding="utf-8-sig") as f:
        extended_rows = list(csv.DictReader(f))

    print(f"Original: {len(original_rows)} rows")
    print(f"Extended: {len(extended_rows)} rows")

    # Compute separately
    orig_results = compute_recall(original_rows, "ORIGINAL (n=19)")
    ext_results = compute_recall(extended_rows, "EXTENDED (n=26)")

    # Compute combined
    combined = original_rows + extended_rows
    combined_results = compute_recall(combined, "COMBINED")

    # Save combined results
    output = {
        "total_advisories": combined_results["total_advisories"],
        "skipped": combined_results["skipped"],
        "total_gt_functions": combined_results["total_gt_functions"],
        "total_matched": combined_results["total_matched"],
        "aggregate_recall_pct": combined_results["aggregate_recall_pct"],
        "at_least_one": combined_results["at_least_one"],
        "at_least_one_pct": combined_results["at_least_one_pct"],
        "perfect": combined_results["perfect"],
        "original": {
            "n": orig_results["total_advisories"],
            "at_least_one": orig_results["at_least_one"],
            "aggregate_pct": orig_results["aggregate_recall_pct"],
        },
        "extended": {
            "n": ext_results["total_advisories"],
            "at_least_one": ext_results["at_least_one"],
            "aggregate_pct": ext_results["aggregate_recall_pct"],
        },
    }

    with open(OUTPUT_JSON, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to {OUTPUT_JSON.name}")


if __name__ == "__main__":
    main()
