#!/usr/bin/env python3
"""
compute_recall.py — Compute recall estimate from the 20-advisory manual study.

Reads recall_study_samples.csv (with author-filled ground_truth_functions)
and computes:
  - Per-advisory recall = |extracted ∩ ground_truth| / |ground_truth|
  - Aggregate recall across all advisories
  - Breakdown by ecosystem
"""

import csv
import sys
from pathlib import Path
from collections import defaultdict

HERE = Path(__file__).resolve().parent
SAMPLES = HERE / "recall_study_samples.csv"


def normalize(name):
    """Normalize a function name for comparison."""
    return name.strip().lower().replace("_", "").replace("-", "")


def parse_functions(field):
    """Parse a semicolon-separated function list."""
    if not field or not field.strip():
        return set()
    return {f.strip() for f in field.split(";") if f.strip()}


def main():
    rows = list(csv.DictReader(open(SAMPLES, encoding="utf-8-sig")))

    print("=" * 70)
    print("RECALL ESTIMATE — 20-Advisory Manual Study")
    print("=" * 70)

    results = []
    skipped = []

    for r in rows:
        vuln_id = r["vuln_id"]
        ecosystem = r["ecosystem"]
        extracted = parse_functions(r["extracted_functions"])
        ground_truth = parse_functions(r["ground_truth_functions"])
        notes = r.get("notes", "")

        # Skip advisories with no ground truth (bulk deletions etc.)
        if not ground_truth:
            skipped.append((vuln_id, notes))
            continue

        # Compute overlap using normalized names
        extracted_norm = {normalize(f): f for f in extracted}
        gt_norm = {normalize(f): f for f in ground_truth}

        # Match: any extracted name that matches a ground truth name
        matched = set()
        for en, e_orig in extracted_norm.items():
            for gn, g_orig in gt_norm.items():
                # Exact match or one is a suffix of the other (class.method vs method)
                if en == gn or en.endswith(gn) or gn.endswith(en):
                    matched.add(g_orig)

        recall = len(matched) / len(ground_truth) if ground_truth else 0
        precision_local = len(matched) / len(extracted) if extracted else 0

        results.append({
            "vuln_id": vuln_id,
            "ecosystem": ecosystem,
            "extracted": extracted,
            "ground_truth": ground_truth,
            "matched": matched,
            "recall": recall,
            "precision_local": precision_local,
            "missed_gt": ground_truth - matched,
            "extra_extracted": extracted - {en for en in extracted
                                            if normalize(en) in
                                            {normalize(m) for m in matched}},
        })

    # Print per-advisory results
    print(f"\n{'Advisory':<30s} {'Eco':<6s} {'Extr':>4s} {'GT':>4s} {'Match':>5s} "
          f"{'Recall':>7s} {'Missed GT'}")
    print("-" * 90)

    total_gt = 0
    total_matched = 0
    eco_stats = defaultdict(lambda: {"gt": 0, "matched": 0, "n": 0})

    for r in results:
        missed_str = "; ".join(sorted(r["missed_gt"]))[:30] if r["missed_gt"] else "-"
        print(f"{r['vuln_id']:<30s} {r['ecosystem']:<6s} {len(r['extracted']):>4d} "
              f"{len(r['ground_truth']):>4d} {len(r['matched']):>5d} "
              f"{r['recall']:>6.1%}  {missed_str}")
        total_gt += len(r["ground_truth"])
        total_matched += len(r["matched"])
        eco_stats[r["ecosystem"]]["gt"] += len(r["ground_truth"])
        eco_stats[r["ecosystem"]]["matched"] += len(r["matched"])
        eco_stats[r["ecosystem"]]["n"] += 1

    # Skipped
    if skipped:
        print(f"\nSkipped ({len(skipped)}):")
        for vid, notes in skipped:
            print(f"  {vid}: {notes[:70]}")

    # Aggregate
    print(f"\n{'=' * 70}")
    print(f"AGGREGATE RECALL")
    print(f"{'=' * 70}")

    agg_recall = total_matched / total_gt if total_gt else 0
    print(f"  Total ground-truth functions: {total_gt}")
    print(f"  Total matched by extraction:  {total_matched}")
    print(f"  Aggregate recall:             {agg_recall:.1%} ({total_matched}/{total_gt})")

    # Per-advisory mean recall
    recalls = [r["recall"] for r in results]
    mean_recall = sum(recalls) / len(recalls) if recalls else 0
    print(f"  Mean per-advisory recall:     {mean_recall:.1%} (n={len(results)})")

    # By ecosystem
    print(f"\n  By ecosystem:")
    for eco in sorted(eco_stats):
        s = eco_stats[eco]
        eco_recall = s["matched"] / s["gt"] if s["gt"] else 0
        print(f"    {eco:>5s}: {eco_recall:.1%} ({s['matched']}/{s['gt']}, "
              f"n={s['n']} advisories)")

    # Save summary for check_consistency.py
    summary = {
        "total_advisories": len(results),
        "skipped": len(skipped),
        "total_gt": total_gt,
        "total_matched": total_matched,
        "aggregate_recall": round(agg_recall * 100, 1),
        "mean_recall": round(mean_recall * 100, 1),
    }
    import json
    out = HERE / "recall_study_results.json"
    out.write_text(json.dumps(summary, indent=2))
    print(f"\nSummary saved to {out}")


if __name__ == "__main__":
    main()
